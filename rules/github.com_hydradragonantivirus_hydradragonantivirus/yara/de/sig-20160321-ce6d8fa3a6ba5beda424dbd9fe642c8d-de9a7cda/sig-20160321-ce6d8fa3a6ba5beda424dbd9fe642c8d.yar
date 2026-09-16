rule sig_20160321_ce6d8fa3a6ba5beda424dbd9fe642c8d {
  meta:
    description = "datamaliciousorder - file 20160321_ce6d8fa3a6ba5beda424dbd9fe642c8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe470681b15ac182fb9fb1bd60b3d45a9a7db6e568f000cc8b474f2ec5582b5e"

  strings:
    $s1  = "return WScript.CreateObject(BNTAR);" fullword ascii
    $s2  = "var Sx = true  , dbZm = KZP[7] + KZP[9] + KZP[11];" fullword ascii
    $s3  = "return DFPPVuw[0] + DFPPVuw[2] + DFPPVuw[4] + \".F\" + DFPPVuw[7] + DFPPVuw[9] + DFPPVuw[12] + DFPPVuw[14];" fullword ascii
    $s4  = "wWPBI.open(wbsTb,evSaO,false);" fullword ascii
    $s5  = "var DFPPVuw = naBDy(nBprBpUmKy+\" \"+\"System Cv cXNDM Obj pqJszK ect TBzHmvZ EOQMZ\", \" \");" fullword ascii
    $s6  = "var KZP = (\"2.XMLHTTP tBNstBT nRBOR XML ream St qYqyHWRL AD wYowMWr O unOM D\").split(\" \");" fullword ascii
    $s7  = "if(i>=q.length) {break;}" fullword ascii
    $s8  = "function MZfe(VyCrv) {" fullword ascii
    $s9  = "return XSeSHid(Ux,MJjgp[132-126]+MJjgp[969-962]+MJjgp[977-969]);" fullword ascii
    $s10 = "function gGiyl(RCgHIc) {" fullword ascii
    $s11 = "if (g >= VyCrv.length) {break;}" fullword ascii
    $s12 = "function ebsl(SALUo) {" fullword ascii
    $s13 = "function GwBZatCUM(KiQqaQUqlxc) {" fullword ascii
    $s14 = "function zrCl(rCBsg) {" fullword ascii
    $s15 = "function XwbF(BNTAR) {" fullword ascii
    $s16 = "return vOo.size;" fullword ascii
    $s17 = "return RCgHIc.position=663-663;" fullword ascii
    $s18 = "FBY = i; break; " fullword ascii
    $s19 = "if (rCBsg == 783-583){return true;} else {return false;}" fullword ascii
    $s20 = "function cdjV(fRUYt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}