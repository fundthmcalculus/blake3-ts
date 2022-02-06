import {encode} from 'fastestsmallesttextencoderdecoder';

class Blake3 {
    public static DEFAULT_HASH_LEN: number = 32;
    public static OUT_LEN: number = 32;
    public static KEY_LEN: number = 32;
    public static BLOCK_LEN: number = 64;
    public static CHUNK_LEN: number = 1024;
    public static CHUNK_START: number = 1;
    public static CHUNK_END: number = 2;
    public static PARENT: number = 4;
    public static ROOT: number = 8;
    public static KEYED_HASH: number = 16;
    public static DERIVE_KEY_CONTEXT: number = 32;
    public static DERIVE_KEY_MATERIAL: number = 64;
    public static IV = new Int32Array([0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]);
    public static MSG_PERMUTATION = new Int32Array([2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]);
    public static HEX_ARRAY: string = "0123456789abcdef"

    public static wrappingAdd(a: number, b: number): number {
        return (a + b);
    }

    public static rotateRight(x: number, len: number): number {
        return (x >>> len) | (x << (32 - len));
    }

    public static g(state: Int32Array, a: number, b: number, c: number, d: number, mx: number, my: number) {
        state[a] = Blake3.wrappingAdd(Blake3.wrappingAdd(state[a], state[b]), mx);
        state[d] = Blake3.rotateRight((state[d] ^ state[a]), 16);
        state[c] = Blake3.wrappingAdd(state[c], state[d]);
        state[b] = Blake3.rotateRight((state[b] ^ state[c]), 12);
        state[a] = Blake3.wrappingAdd(Blake3.wrappingAdd(state[a], state[b]), my);
        state[d] = Blake3.rotateRight((state[d] ^ state[a]), 8);
        state[c] = Blake3.wrappingAdd(state[c], state[d]);
        state[b] = Blake3.rotateRight((state[b] ^ state[c]), 7);
    }

    public static roundFn(state: Int32Array, m: Int32Array) {
        // Mix columns
        Blake3.g(state, 0, 4, 8, 12, m[0], m[1]);
        Blake3.g(state, 1, 5, 9, 13, m[2], m[3]);
        Blake3.g(state, 2, 6, 10, 14, m[4], m[5]);
        Blake3.g(state, 3, 7, 11, 15, m[6], m[7]);

        // Mix diagonals
        Blake3.g(state, 0, 5, 10, 15, m[8], m[9]);
        Blake3.g(state, 1, 6, 11, 12, m[10], m[11]);
        Blake3.g(state, 2, 7, 8, 13, m[12], m[13]);
        Blake3.g(state, 3, 4, 9, 14, m[14], m[15]);
    }

    public static permute(m: Int32Array): Int32Array {
        let permuted: number[] = [];
        for (let i = 0; i < 16; i++) {
            permuted[i] = m[(Blake3.MSG_PERMUTATION)[i]];
        }
        return new Int32Array(permuted);
    }

    public static compress(chainingValue: Int32Array, blockWords: Int32Array, counter: bigint | number, blockLen: number, flags: number): Int32Array {
        counter = BigInt(counter)
        let counterInt = Number(counter & BigInt(0xffffffff))
        let counterShift = Number((counter >> BigInt(32)) & BigInt(0xffffffff))
        let state = new Int32Array([chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3], chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7], (Blake3.IV)[0], (Blake3.IV)[1], (Blake3.IV)[2], (Blake3.IV)[3], counterInt, counterShift, blockLen, flags]);
        Blake3.roundFn(state, blockWords);         // Round 1
        blockWords = Blake3.permute(blockWords);
        Blake3.roundFn(state, blockWords);         // Round 2
        blockWords = Blake3.permute(blockWords);
        Blake3.roundFn(state, blockWords);         // Round 3
        blockWords = Blake3.permute(blockWords);
        Blake3.roundFn(state, blockWords);         // Round 4
        blockWords = Blake3.permute(blockWords);
        Blake3.roundFn(state, blockWords);         // Round 5
        blockWords = Blake3.permute(blockWords);
        Blake3.roundFn(state, blockWords);         // Round 6
        blockWords = Blake3.permute(blockWords);
        Blake3.roundFn(state, blockWords);         // Round 7

        for (let i = 0; i < 8; i++) {
            state[i] ^= state[i + 8];
            state[i + 8] ^= chainingValue[i];
        }
        return new Int32Array(state);
    }

    public static wordsFromLEBytes(bytes: Uint8Array): Int32Array {
        return new Int32Array(bytes);
    }

    // Hasher
    private chunkState: ChunkState;
    private key: Int32Array;
    private  cvStack: Int32Array[] = [new Int32Array()]; // Preallocate to 54 elements?
    private cvStackLen: number = 0;
    private flags: number;


private constructor( context?: string, key?: Uint8Array){
        if (!context) {
            this.initialize(Blake3.IV,0);
            return
        }
        if (!key) {
            this.initialize(Blake3.wordsFromLEBytes(key), Blake3.KEYED_HASH);
        }
    let contextHasher = new Blake3();
    contextHasher.initialize(Blake3.IV, Blake3.DERIVE_KEY_CONTEXT);
    contextHasher.update(encode(context)); // UTF-8 only
    let contextKey = Blake3.wordsFromLEBytes(contextHasher.digest());
    this.initialize(contextKey, Blake3.DERIVE_KEY_MATERIAL);
}

private initialize(key: Int32Array, flags: number){
    this.chunkState = new ChunkState(key, 0, flags);
    this.key = key;
    this.flags = flags;
}

/**
 * Append the byte contents of the file to the hash tree
 * @param file File to be added
 * @throws IOException If the file does not exist
 */
// TODO - Support loading from files somehow?
// public update(File file) throws IOException {
//     // Update the hasher 4kb at a time to avoid memory issues when hashing large files
//     try(InputStream ios = new FileInputStream(file)){
//         byte[] buffer = new byte[4096];
//         int read = 0;
//         while((read = ios.read(buffer)) != -1){
//             if(read == buffer.length) {
//                 update(buffer);
//             } else {
//                 update(Arrays.copyOfRange(buffer, 0, read));
//             }
//         }
//     }
// }

/**
 * Appends new data to the hash tree
 * @param input Data to be added
 */
public update(input: Uint8Array){
    let currPos = 0;
    while(currPos < input.length) {

        // If this chunk has chained in 16 64 bytes of input, add its CV to the stack
        if (this.chunkState.len() == Blake3.CHUNK_LEN) {
            let chunkCV = this.chunkState.createNode().chainingValue();
            let totalChunks = this.chunkState.chunkCounter + BigInt(1);
            this.addChunkChainingValue(chunkCV, totalChunks);
            this.chunkState = new ChunkState(this.key, totalChunks, this.flags);
        }

        let want = Blake3.CHUNK_LEN - this.chunkState.len();
        let take = Math.min(want, input.length - currPos);
        this.chunkState.update(input.slice(currPos, currPos + take));
        currPos+=take;
    }
}

/**
 * Generate the blake3 hash for the current tree with the given byte length, default 32
 * @param hashLen The number of bytes of hash to return
 * @return The byte array representing the hash
 */
public digest(hashLen?: number): Uint8Array {
    if (!hashLen) return this.digest(Blake3.DEFAULT_HASH_LEN);

    let node = this.chunkState.createNode();
    let parentNodesRemaining = this.cvStackLen;
    while(parentNodesRemaining > 0){
        parentNodesRemaining -=1;
        node = Blake3.parentNode(
            new Int32Array((this.cvStack)[parentNodesRemaining]),
            node.chainingValue(),
            this.key,
            this.flags
        );
    }
    return node.rootOutputBytes(hashLen);
}

/**
 * Generate the blake3 hash for the current tree with the given byte length (default byte length of 32)
 * @param hashLen The number of bytes of hash to return
 * @return The hex string representing the hash
 */
public hexdigest( hashLen?: number): string{
    if (!hashLen) return this.hexdigest(Blake3.DEFAULT_HASH_LEN);
    return Blake3.bytesToHex(this.digest(hashLen));
}

private pushStack( cv: Int32Array){
    this.cvStack[this.cvStackLen] = cv;
    this.cvStackLen+=1;
}

private popStack(): Int32Array{
    this.cvStackLen-=1;
    return this.cvStack[this.cvStackLen];
}

// Combines the chaining values of two children to create the parent node
private static parentNode( leftChildCV: Int32Array,  rightChildCV: Int32Array,  key: Int32Array, flags: number): Node{
    let blockWords = new Int32Array(16);
    let i = 0;
    for(let x of leftChildCV){
        blockWords[i] = x;
        i+=1;
    }
    for(let x of rightChildCV){
        blockWords[i] = x;
        i+=1;
    }
    return new Node(key, blockWords, 0, Blake3.BLOCK_LEN, Blake3.PARENT | flags);
}

private static  parentCV( leftChildCV: Int32Array,  rightChildCV: Int32Array,  key: Int32Array, flags: number): Int32Array{
    return this.parentNode(leftChildCV, rightChildCV, key, flags).chainingValue();
}

private addChunkChainingValue(newCV: Int32Array, totalChunks: bigint) {
    while((totalChunks & BigInt(1)) == BigInt(0)) {
        newCV = Blake3.parentCV(this.popStack(), newCV, this.key, this.flags);
        totalChunks >>= BigInt(1);
    }
    this.pushStack(newCV);
}

private static bytesToHex(bytes: Uint8Array): string {
    let hexChars: string
    for (let j = 0; j < bytes.length; j++) {
        let v = bytes[j] & 0xFF;
        hexChars += Blake3.HEX_ARRAY[v >>> 4];
        hexChars += Blake3.HEX_ARRAY[v & 0x0F];
    }
    return hexChars
}

/**
 * Construct a BLAKE3 blake3 hasher
 */
public static newInstance(): Blake3{
    return new Blake3();
}

/**
 * Construct a new BLAKE3 keyed mode hasher
 * @param key The 32 byte key
 * @throws IllegalStateException If the key is not 32 bytes
 */
public static newKeyedHasher(key: Uint8Array): Blake3{
    if(!(key.length == Blake3.KEY_LEN)) throw new Error("Invalid key length");
    return new Blake3(null, key);
}

/**
 * Construct a new BLAKE3 key derivation mode hasher
 * The context string should be hardcoded, globally unique, and application-specific. <br><br>
 * A good default format is <i>"[application] [commit timestamp] [purpose]"</i>, <br>
 * eg "example.com 2019-12-25 16:18:03 session tokens v1"
 * @param context Context string used to derive keys.
 */
public static newKeyDerivationHasher( context: string): Blake3 {
    return new Blake3(context);
}
}

class Node {
    inputChainingValue: Int32Array;
    blockWords: Int32Array;
    counter: bigint;
    blockLen: number;
    flags: number;

    public constructor(inputChainingValue: Int32Array, blockWords: Int32Array, counter: bigint | number, blockLen: number, flags: number) {
        this.inputChainingValue = inputChainingValue;
        this.blockWords = blockWords;
        this.counter = BigInt(counter);
        this.blockLen = blockLen;
        this.flags = flags;
    }

// Return the 8 int CV
    public chainingValue(): Int32Array {
        return Blake3.compress(this.inputChainingValue, this.blockWords, this.counter, this.blockLen, this.flags).slice(0, 8);
    }

    public rootOutputBytes(outLen: number): Uint8Array {
        let outputCounter = 0;
        let outputsNeeded = Math.floor(outLen / ((2 * Blake3.OUT_LEN) + 1));
        let hash: Uint8Array = new Uint8Array();
        let i = 0;
        while (outputCounter < outputsNeeded) {
            let words = Blake3.compress(this.inputChainingValue, this.blockWords, outputCounter, this.blockLen, this.flags | Blake3.ROOT);

            for (let i = 0; i < words.length; i++) {
                let word = new Uint8Array([words[i]]);
                for (let j = 0; j < word.length; j++) {
                    hash[i] = word[j];
                    i += 1;
                    if (i == outLen) {
                        return hash;
                    }
                }
            }
            outputCounter += 1;
        }
        throw new Error("Uh oh something has gone horribly wrong. Please create an issue on https://github.com/fundthmcalculus/blake3-ts");
    }
}

class ChunkState {
    chainingValue: Int32Array;
    chunkCounter: bigint;
    block: Uint8Array = new Uint8Array(Blake3.BLOCK_LEN)
    blockLen: number = 0;
    blocksCompressed: number = 0;
    flags: number;

    public constructor(key: Int32Array, chunkCounter: bigint | number, flags: number) {
        this.chainingValue = key;
        this.chunkCounter = BigInt(chunkCounter);
        this.flags = flags;
    }

    public len(): number {
        return Blake3.BLOCK_LEN * this.blocksCompressed + this.blockLen;
    }

    private startFlag(): number {
        return this.blocksCompressed == 0 ? Blake3.CHUNK_START : 0;
    }

    update(input: Uint8Array) {
        let currPos = 0;
        while (currPos < input.length) {

            // Chain the next 64 byte block into this chunk/node
            if (this.blockLen == Blake3.BLOCK_LEN) {
                let blockWords = Blake3.wordsFromLEBytes(this.block);
                this.chainingValue = Blake3.compress(this.chainingValue, blockWords, this.chunkCounter, Blake3.BLOCK_LEN, this.flags | this.startFlag()).slice(0, 8);
                this.blocksCompressed += 1;
                this.block = new Uint8Array(Blake3.BLOCK_LEN);
                this.blockLen = 0;
            }

            // Take bytes out of the input and update
            let want: number = Blake3.BLOCK_LEN - this.blockLen; // How many bytes we need to fill up the current block
            let canTake: number = Math.min(want, input.length - currPos);

            arraycopy(input, currPos, this.block, this.blockLen, canTake);
            this.blockLen += canTake;
            currPos += canTake;
        }
    }

    createNode(): Node {
        return new Node(this.chainingValue, Blake3.wordsFromLEBytes(this.block), this.chunkCounter, this.blockLen, this.flags | this.startFlag() | Blake3.CHUNK_END);
    }
}

function arraycopy(sourceArray, sourcePos, destArray, destPos, length) {
    for (let i = 0; i < length; i++) {
        destArray[destPos + i] = sourceArray[sourcePos + i]
    }
}