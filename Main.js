
class Sha3 {

    static hash224(message, options) {
        return Sha3.keccak1600(1152, 448, message, options);
    }

    static hash256(message, options) {
        return Sha3.keccak1600(1088, 512, message, options);
    }

    static hash384(message, options) {
        return Sha3.keccak1600(832, 768, message, options);
    }

    static hash512(message, options) {
        return Sha3.keccak1600(576, 1024, message, options);
    }

    static keccak1600(r, c, M, options) {
        const defaults = { padding: 'sha-3', msgFormat: 'string', outFormat: 'hex' };
        const opt = Object.assign(defaults, options);

        const l = c / 2; 

        let msg = null;
        switch (opt.msgFormat) {
            default: 
            case 'string':    msg = utf8Encode(M);       break;
            case 'hex-bytes': msg = hexBytesToString(M); break; 
        }

        const state = [ [], [], [], [], [] ];
        for (let x=0; x<5; x++) {
            for (let y=0; y<5; y++) {
                state[x][y] = 0n;
            }
        }

        
        const q = (r/8) - msg.length % (r/8);
        if (q == 1) {
            msg += String.fromCharCode(opt.padding=='keccak' ? 0x81 : 0x86);
        } else {
            msg += String.fromCharCode(opt.padding=='keccak' ? 0x01 : 0x06);
            msg += String.fromCharCode(0x00).repeat(q-2);
            msg += String.fromCharCode(0x80);
        }

        

        const w = 64; 
        const blocksize = r / w * 8; 

        for (let i=0; i<msg.length; i+=blocksize) {
            for (let j=0; j<r/w; j++) {
                const i64 = (BigInt(msg.charCodeAt(i+j*8+0))<< 0n) + (BigInt(msg.charCodeAt(i+j*8+1))<< 8n)
                          + (BigInt(msg.charCodeAt(i+j*8+2))<<16n) + (BigInt(msg.charCodeAt(i+j*8+3))<<24n)
                          + (BigInt(msg.charCodeAt(i+j*8+4))<<32n) + (BigInt(msg.charCodeAt(i+j*8+5))<<40n)
                          + (BigInt(msg.charCodeAt(i+j*8+6))<<48n) + (BigInt(msg.charCodeAt(i+j*8+7))<<56n);
                const x = j % 5;
                const y = Math.floor(j / 5);
                state[x][y] = state[x][y] ^ i64;
            }
            Sha3.keccak_f_1600(state);
        }

        

        
        let md = transpose(state)
            .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0').match(/.{2}/g).reverse().join('')).join(''))
            .join('')
            .slice(0, l/4);

        
        if (opt.outFormat == 'hex-b') md = md.match(/.{2}/g).join(' ');
        if (opt.outFormat == 'hex-w') md = md.match(/.{8,16}/g).join(' ');

        return md;

        function transpose(array) { 
            return array.map((row, r) => array.map(col => col[r]));
        }

        function utf8Encode(str) {
            try {
                return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
            } catch (e) { 
                return unescape(encodeURIComponent(str)); 
            }
        }

        function hexBytesToString(hexStr) { 
            const str = hexStr.replace(' ', ''); 
            return str=='' ? '' : str.match(/.{2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
        }
    }

    static keccak_f_1600(a) {

        const nRounds = 24; 

        const RC = [
            0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
            0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
            0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
            0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
            0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
            0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
            0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
            0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
        ];

        
        for (let r=0; r<nRounds; r++) {
            

            
            const C = [], D = []; 
            for (let x=0; x<5; x++) {
                C[x] = a[x][0];
                for (let y=1; y<5; y++) {
                    C[x] = C[x] ^ a[x][y];
                }
            }
            for (let x=0; x<5; x++) {
                
                D[x] = C[(x+4)%5] ^ ROT(C[(x+1)%5], 1);
                
                for (let y=0; y<5; y++) {
                    a[x][y] = a[x][y] ^ D[x];
                }
            }

            
            let [ x, y ] = [ 1, 0 ];
            let current = a[x][y];
            for (let t=0; t<24; t++) {
                const [ X, Y ] = [ y, (2*x + 3*y) % 5 ];
                const tmp = a[X][Y];
                a[X][Y] = ROT(current, ((t+1)*(t+2)/2) % 64);
                current = tmp;
                [ x, y ] = [ X, Y ];
            }
           
            for (let y=0; y<5; y++) {
                const C = [];  
                for (let x=0; x<5; x++) C[x] = a[x][y];
                for (let x=0; x<5; x++) {
                    a[x][y] = (C[x] ^ ((~C[(x+1)%5]) & C[(x+2)%5]));
                }
            }

            
            a[0][0] = (a[0][0] ^ RC[r]);
        }

        function ROT(a, d) { 
            return BigInt.asUintN(64, a << BigInt(d) | a >> BigInt(64-d));
        }

        function debugNist(s) { 
            const d = transpose(s)
                .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0').match(/.{2}/g).reverse().join('')).join(''))
                .join('')
                .match(/.{2}/g).join(' ')
                .match(/.{23,48}/g).join('\n');
            console.info(d);
        }

        function debug5x5(s) { 
            const d = transpose(s)
                .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0')).join(' '))
                .join('\n');
            console.info(d);
        }

        function transpose(array) { 
            return array.map((row, r) => array.map(col => col[r]));
        }
    }

}