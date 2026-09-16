rule sig_20160527_236df1d5d0e0a402790de12748a4119f {
  meta:
    description = "datamaliciousorder - file 20160527_236df1d5d0e0a402790de12748a4119f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9686e5cd0e1c9ec6481c92e6c28df45fba8af37d64284566a6cb122dda1db51e"

  strings:
    $s1  = "function mKDKxNMalUF() {return WScript;}function eEBhy(){return XMTDN.ExpandEnvironmentStrings(YNhghNbZcYIL())}" fullword ascii
    $s2  = "function PMuHcWjyToeRmvtstnaXffbn(HtbKOMuyfUted,iQigiZIHYYuJjnakceMVCN){return HtbKOMuyfUted.charAt(iQigiZIHYYuJjnakceMVCN);}" fullword ascii
    $s3  = "hqjM[3])+String.fromCharCode(92)+kbRuNabswnjuEewukUsdhqjM[4],true);" fullword ascii
    $s4  = "var nqsaLWeoVDZp=function(){return new ActiveXObject(kbRuNabswnjuEewukUsdhqjM[0]);}();" fullword ascii
    $s5  = "function HFARdgHoGkbYJ(fgJYljxwHovIVU,FJcVIPUyNIAU) {var wsQAgGczLoo=[kbRuNabswnjuEewukUsdhqjM[15]];fgJYljxwHovIVU[wsQAgGczLoo[0" ascii
    $s6  = "function DKmUQ(){return uAXDLZWqgZJ(kbRuNabswnjuEewukUsdhqjM[10],[2,4,8,10],kbRuNabswnjuEewukUsdhqjM[11]);}" fullword ascii
    $s7  = "var XMTDN=function(){return mKDKxNMalUF().CreateObject(kbRuNabswnjuEewukUsdhqjM[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "var pnkffWjGGAYZGc = nqsaLWeoVDZp.createtextfile(XMTDN.ExpandEnvironmentStrings(kbRuNabswnjuEewukUsdhqjM[2]+kbRuNabswnjuEewukUsd" ascii
    $s9  = "function uAXDLZWqgZJ(ICCQFkm,zGjZRzTvhMgQ,eMpFMKeJ){abUGEktAk=ICCQFkm.split(eMpFMKeJ);bpVnz = kbRuNabswnjuEewukUsdhqjM[14];for(r" ascii
    $s10 = "function ylaMmzXjss(zNEaoERWESWcV) {var BxsmIBbNwsMXOFQjKoVzA = UbRxYIlhzgNIRqUhqf.join(kbRuNabswnjuEewukUsdhqjM[6]);var GnmvXZE" ascii
    $s11 = "function uAXDLZWqgZJ(ICCQFkm,zGjZRzTvhMgQ,eMpFMKeJ){abUGEktAk=ICCQFkm.split(eMpFMKeJ);bpVnz = kbRuNabswnjuEewukUsdhqjM[14];for(r" ascii
    $s12 = "function RTHCHxRBCh(){return uAXDLZWqgZJ(kbRuNabswnjuEewukUsdhqjM[12],[0,3,6],kbRuNabswnjuEewukUsdhqjM[13]);}" fullword ascii
    $s13 = "function HFARdgHoGkbYJ(fgJYljxwHovIVU,FJcVIPUyNIAU) {var wsQAgGczLoo=[kbRuNabswnjuEewukUsdhqjM[15]];fgJYljxwHovIVU[wsQAgGczLoo[0" ascii
    $s14 = "function ylaMmzXjss(zNEaoERWESWcV) {var BxsmIBbNwsMXOFQjKoVzA = UbRxYIlhzgNIRqUhqf.join(kbRuNabswnjuEewukUsdhqjM[6]);var GnmvXZE" ascii
    $s15 = "function YNhghNbZcYIL(){return uAXDLZWqgZJ(kbRuNabswnjuEewukUsdhqjM[8],[1,5,7],kbRuNabswnjuEewukUsdhqjM[9]);}" fullword ascii
    $s16 = "function SAcbpRC(EpxmnGYzIVn,AgZzpDcHUYqiISg,JJwADxAgLgunxZUCqVjLmtM){return String.fromCharCode(EpxmnGYzIVn,AgZzpDcHUYqiISg,JJw" ascii
    $s17 = "function xmivjCsfyzeXNaFjHz(ztSbkhBYVZjk,vLcpJOq){return ztSbkhBYVZjk.indexOf(vLcpJOq);}" fullword ascii
    $s18 = "GnmvXZErBkeLfMhvmiaR, kEnGzxyBQFroBCKLHOOx, FSeQVtOPkHQF);} while (cuymSHuigQs < zNEaoERWESWcV.length);return tvtrYejVHfHJKy;}" fullword ascii
    $s19 = "function SAcbpRC(EpxmnGYzIVn,AgZzpDcHUYqiISg,JJwADxAgLgunxZUCqVjLmtM){return String.fromCharCode(EpxmnGYzIVn,AgZzpDcHUYqiISg,JJw" ascii
    $s20 = "zMNZuZ>> 8 & 0xff;FSeQVtOPkHQF = QzMNZuZ & 0xff;if (xTPhdCwboisdOzxQFlDJ == 64) tvtrYejVHfHJKy += Yv(GnmvXZErBkeLfMhvmiaR);else " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}