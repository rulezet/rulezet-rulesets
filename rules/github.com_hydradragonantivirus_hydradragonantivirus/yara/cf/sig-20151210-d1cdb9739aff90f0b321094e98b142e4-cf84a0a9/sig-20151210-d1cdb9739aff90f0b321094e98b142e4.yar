rule sig_20151210_d1cdb9739aff90f0b321094e98b142e4 {
  meta:
    description = "datamaliciousorder - file 20151210_d1cdb9739aff90f0b321094e98b142e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc52c96ea6827badfd8b61578a6c4184251ff3ac5152e8eb0266bfb6522e27fe"

  strings:
    $s1  = "function hsCQhsL(LgTeUAFIIBztAHWXmaYbxQwxKeyJtyTwnTrK) {return !isNaN(parseFloat(LgTeUAFIIBztAHWXmaYbxQwxKeyJtyTwnTrK)) && isFin" ascii
    $s2  = "function hsCQhsL(LgTeUAFIIBztAHWXmaYbxQwxKeyJtyTwnTrK) {return !isNaN(parseFloat(LgTeUAFIIBztAHWXmaYbxQwxKeyJtyTwnTrK)) && isFin" ascii
    $s3  = "function jfDeNBcXlfufyxhMw(xksrB){VnCRHTQydmi= '';for(xCohjPRdvaZ=(-255+255)/13; xCohjPRdvaZ < (759+365)/562; xCohjPRdvaZ++) {gX" ascii
    $s4  = "function FSohi(uxmXGFeiSQu,IIFPbPLTppiAV,vBPwLfoX){nrJp=parseInt(uxmXGFeiSQu,IIFPbPLTppiAV);vEmgX=nrJp.toString(vBPwLfoX);return" ascii
    $s5  = "function uGAVanMaKQS(GjSAUyBx,eFElHH){return GjSAUyBx.split(eFElHH)}" fullword ascii
    $s6  = "mROIbgY=(-561+561)/776;while(true){if(mROIbgY>=(3896+968)/38){break;}fxIAlpOYQyGYg[mROIbgY]=String.fromCharCode(mROIbgY);mROIbgY" ascii
    $s7  = "gskmCyI[xCohjPRdvaZ]=(-576+576)/990; while(true) { if(gXgskmCyI[xCohjPRdvaZ] > xksrB[xCohjPRdvaZ].length-(276+354)/630) { break;" ascii
    $s8  = "function FSohi(uxmXGFeiSQu,IIFPbPLTppiAV,vBPwLfoX){nrJp=parseInt(uxmXGFeiSQu,IIFPbPLTppiAV);vEmgX=nrJp.toString(vBPwLfoX);return" ascii
    $s9  = "function JgMPNdioorGOSxeHgOLZkBMYQhepjwIWjvsHTkPlshsefRegdlypWW(NhLxFYhMjQKlS,CtAMtbHvJutqSu){ return fxIAlpOYQyGYg[FSohi(NhLxFY" ascii
    $s10 = " vEmgX;}function CsZtHVeISxexiuw(njSjGfNmzWAIzstNF){eval(njSjGfNmzWAIzstNF)}" fullword ascii
    $s11 = "function JgMPNdioorGOSxeHgOLZkBMYQhepjwIWjvsHTkPlshsefRegdlypWW(NhLxFYhMjQKlS,CtAMtbHvJutqSu){ return fxIAlpOYQyGYg[FSohi(NhLxFY" ascii
    $s12 = "mROIbgY=(-561+561)/776;while(true){if(mROIbgY>=(3896+968)/38){break;}fxIAlpOYQyGYg[mROIbgY]=String.fromCharCode(mROIbgY);mROIbgY" ascii
    $s13 = ";}} return VnCRHTQydmi}" fullword ascii
    $s14 = "function jfDeNBcXlfufyxhMw(xksrB){VnCRHTQydmi= '';for(xCohjPRdvaZ=(-255+255)/13; xCohjPRdvaZ < (759+365)/562; xCohjPRdvaZ++) {gX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}