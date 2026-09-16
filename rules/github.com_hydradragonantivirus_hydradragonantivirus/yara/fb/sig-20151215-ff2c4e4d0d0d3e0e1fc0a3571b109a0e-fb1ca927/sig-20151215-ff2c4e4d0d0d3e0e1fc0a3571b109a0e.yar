rule sig_20151215_ff2c4e4d0d0d3e0e1fc0a3571b109a0e {
  meta:
    description = "datamaliciousorder - file 20151215_ff2c4e4d0d0d3e0e1fc0a3571b109a0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40461865e1e9b8b5193f49f485bfc20e0de70eb99a4579e9aba33354d94450d8"

  strings:
    $s1  = "Math.cos(349), 2) - 1)));} hmKyWqqls[qEyQEUVEeZg]++;}} return XFoMZPoylYJ}" fullword ascii
    $s2  = "function zovycBepvnnwBksfJ(nbhZX){XFoMZPoylYJ= H[1810];for(qEyQEUVEeZg=Math.round((Math.pow(Math.sin(347), 2) + Math.pow(Math.co" ascii
    $s3  = "th.pow(Math.cos(86), 2) - 1)); while(true) { if(hmKyWqqls[qEyQEUVEeZg] > nbhZX[qEyQEUVEeZg].length-(-220+459)/239) { break; } if" ascii
    $s4  = "function zovycBepvnnwBksfJ(nbhZX){XFoMZPoylYJ= H[1810];for(qEyQEUVEeZg=Math.round((Math.pow(Math.sin(347), 2) + Math.pow(Math.co" ascii
    $s5  = "HuUoc)) {return (String.fromCharCode(lmlFKjRURiVHuUoc) + String.fromCharCode((18346+68)/341));}}" fullword ascii
    $s6  = "function LD(XAEGdauOgqcR,sVfFcNpUTgrWmx){XAEGdauOgqcR.push(sVfFcNpUTgrWmx);}function I7(lmlFKjRURiVHuUoc){if(WPDKIET(lmlFKjRURiV" ascii
    $s7  = "function WPDKIET(WnICcZYHGXshjisrYWlBhXkwJXkfFzotfECn) {return !isNaN(parseFloat(WnICcZYHGXshjisrYWlBhXkwJXkfFzotfECn)) && isFin" ascii
    $s8  = "function WPDKIET(WnICcZYHGXshjisrYWlBhXkwJXkfFzotfECn) {return !isNaN(parseFloat(WnICcZYHGXshjisrYWlBhXkwJXkfFzotfECn)) && isFin" ascii
    $s9  = "var H=new Array();" fullword ascii
    $s10 = "function zhDwsAtZdOq(ICSUtyvN,gbCptc){return ICSUtyvN.split(gbCptc)}" fullword ascii
    $s11 = "function EBYeT(lgTsruJMMmt,MBELKTysruOrF,fZFgOmHI){lEoe=parseInt(lgTsruJMMmt,MBELKTysruOrF);Ydnzu=lEoe.toString(fZFgOmHI);return" ascii
    $s12 = " Ydnzu;}function WjfNcXZvCqqLulm(nVBizDbmOJLtdPUmT,aEvicSgyABNfMJYwuHoIiGfIkvBtwjPcjl,wlTqFkUqeZvsUfZjSPgxgkXwGexKaNbBsHa){eval(" ascii
    $s13 = "function EBYeT(lgTsruJMMmt,MBELKTysruOrF,fZFgOmHI){lEoe=parseInt(lgTsruJMMmt,MBELKTysruOrF);Ydnzu=lEoe.toString(fZFgOmHI);return" ascii
    $s14 = "function WjfNcXZvCqqLulm(nVBizDbmOJLtdPUmT){eval(nVBizDbmOJLtdPUmT)}" fullword ascii
    $s15 = "function nABVCOiqkDmituvZymEupyuouBPtUOKMvdAVXgMMRYtHATeFdsHnmq(cojhNMUqfWTEF,FoUjPSaJdFJVYv){ return QwmpLiy[hNfCDOYf[EBYeT(coj" ascii
    $s16 = "function LD(XAEGdauOgqcR,sVfFcNpUTgrWmx){XAEGdauOgqcR.push(sVfFcNpUTgrWmx);}function I7(lmlFKjRURiVHuUoc){if(WPDKIET(lmlFKjRURiV" ascii
    $s17 = "function nABVCOiqkDmituvZymEupyuouBPtUOKMvdAVXgMMRYtHATeFdsHnmq(cojhNMUqfWTEF,FoUjPSaJdFJVYv){ return QwmpLiy[hNfCDOYf[EBYeT(coj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}