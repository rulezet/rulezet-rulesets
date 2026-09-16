rule sig_20160523_a67d97bf3f2368ee7aecc6ffb037eff1 {
  meta:
    description = "datamaliciousorder - file 20160523_a67d97bf3f2368ee7aecc6ffb037eff1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ef237918e61c1da7cf543401e2a90c1173e0ca0debb48671f4fce6a091e63e5"

  strings:
    $s1  = "function uHIkMqDBlV(jGrFMmgx,GSWhzXgcbAtq) {jGrFMmgx.Run(GSWhzXgcbAtq, 0x1, 0x0);}" fullword ascii
    $s2  = "function SROatCkHjn() {return/*ypFlyaiNVaGSSNawKKKbNfNccoICDvGNExAZfZLzqUZObABTMbodGhSRasYfyiLTpwUoupqTnGvLwLrCEjBLaAhEJqnAnZntG" ascii
    $s3  = "function teYEObA(){return Math.random();}" fullword ascii
    $s4  = "function kxIstyK() {var bTUt=100000;var cJxbIh = 100;return teYEObA()*(bTUt-cJxbIh)+cJxbIh;}" fullword ascii
    $s5  = "function sFhhvcRc(RkBNB) {var UkDCalLz=VHjSAkMByDAgKiXR[13];for(var TXJRc=0;TXJRc<RkBNB;TXJRc++){SaHMf+=UkDCalLz.charAt(Math.flo" ascii
    $s6  = "function sFhhvcRc(RkBNB) {var UkDCalLz=VHjSAkMByDAgKiXR[13];for(var TXJRc=0;TXJRc<RkBNB;TXJRc++){SaHMf+=UkDCalLz.charAt(Math.flo" ascii
    $s7  = "function dAPf(VkdqvN,DWZsmFR){tiDu = VHjSAkMByDAgKiXR[10].split(VHjSAkMByDAgKiXR[11]);DWZsmFR.open(tiDu[0]+tiDu[2]+tiDu[3], Vkdq" ascii
    $s8  = "function xSdqS(WlKpUXHv,KTfxbE,XnyjjIuxN){FAXMY=WlKpUXHv.split(XnyjjIuxN);fJdUPqE = VHjSAkMByDAgKiXR[12];for(rPYWNexh=0;rPYWNexh" ascii
    $s9  = "function jBPom(VhfELvdj,kGfvo,tJNBIkgdLS){xukR(VhfELvdj);SKrldSre(VhfELvdj);FlIsltk(VhfELvdj,kGfvo);QJxRIJEld(VhfELvdj);EbvH(Vhf" ascii
    $s10 = "<KTfxbE.length;rPYWNexh++) {fJdUPqE+=FAXMY[KTfxbE[rPYWNexh]];}return fJdUPqE.substring(3,fJdUPqE.length);}" fullword ascii
    $s11 = "vN, false);DWZsmFR.send();}" fullword ascii
    $s12 = "function SKrldSre(IazGDPdUO) {IazGDPdUO.type=1;}" fullword ascii
    $s13 = "if(dggW>yaibi.length) break;" fullword ascii
    $s14 = "function SROatCkHjn() {return/*ypFlyaiNVaGSSNawKKKbNfNccoICDvGNExAZfZLzqUZObABTMbodGhSRasYfyiLTpwUoupqTnGvLwLrCEjBLaAhEJqnAnZntG" ascii
    $s15 = "function cZHcWae(UlqmJ) {UlqmJ.close();}" fullword ascii
    $s16 = "function xSdqS(WlKpUXHv,KTfxbE,XnyjjIuxN){FAXMY=WlKpUXHv.split(XnyjjIuxN);fJdUPqE = VHjSAkMByDAgKiXR[12];for(rPYWNexh=0;rPYWNexh" ascii
    $s17 = "function jBPom(VhfELvdj,kGfvo,tJNBIkgdLS){xukR(VhfELvdj);SKrldSre(VhfELvdj);FlIsltk(VhfELvdj,kGfvo);QJxRIJEld(VhfELvdj);EbvH(Vhf" ascii
    $s18 = "function mQliGN(hWXayW){return hWXayW.ExpandEnvironmentStrings(VHjSAkMByDAgKiXR[9])}" fullword ascii
    $s19 = "function FlIsltk(JEOY,ixNBW) {JEOY.write(ixNBW);}" fullword ascii
    $s20 = "function EbvH(aGwsSlq,HCusTOf) {aGwsSlq.saveToFile(HCusTOf, 2);}" fullword ascii

  condition:
    uint16(0) == 0x2027 and
    8 of them
}