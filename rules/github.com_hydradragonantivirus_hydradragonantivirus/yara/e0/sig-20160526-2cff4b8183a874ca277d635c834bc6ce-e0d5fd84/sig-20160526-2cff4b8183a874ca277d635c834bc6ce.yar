rule sig_20160526_2cff4b8183a874ca277d635c834bc6ce {
  meta:
    description = "datamaliciousorder - file 20160526_2cff4b8183a874ca277d635c834bc6ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "178bd67d3225988e14301d105d0f2a76a5aa3d42df0ca766b128ebd2bf228d5e"

  strings:
    $s1  = "function VTznnNIky(ZfFGLmfgppfdm) {var lEvgmmSKjD = ycHFNDoqPBVWvzNdGgHKpjrX.join(ZppHkF[0]);var LeEeFlAoDVj, FQPwKmekIinX, jdkv" ascii
    $s2  = ".cos(322), 2) - 1))-880)) uCYfzAxylXcXJstNAB += ZiyUYigFG(LeEeFlAoDVj, FQPwKmekIinX);else uCYfzAxylXcXJstNAB += VKAdieKcBgkAahI(" ascii
    $s3  = "CYfzAxylXcXJstNAB += PW(LeEeFlAoDVj);else if (PpsjJSrvYoaYzPUPb == (944 + Math.round((Math.pow(Math.sin(322), 2) + Math.pow(Math" ascii
    $s4  = "function gVWQzxxQOJPaPHIkiNUyTwF(tNuTpNKFNNDUDRwZZCeUYg,llpVFEGf){return tNuTpNKFNNDUDRwZZCeUYg.charAt(llpVFEGf);}" fullword ascii
    $s5  = "function VKAdieKcBgkAahI(hksWwUwardpsmEibf,TWHCMpbdKkVwnk,KEyhFtLfGXDYHpSiOaOiBclm){return String.fromCharCode(hksWwUwardpsmEibf" ascii
    $s6  = "function VKAdieKcBgkAahI(hksWwUwardpsmEibf,TWHCMpbdKkVwnk,KEyhFtLfGXDYHpSiOaOiBclm){return String.fromCharCode(hksWwUwardpsmEibf" ascii
    $s7  = "LeEeFlAoDVj, FQPwKmekIinX, jdkvrxBKtvFaWRhc);} while (oJmGlFTaJPZvEkhA < ZfFGLmfgppfdm.length);return uCYfzAxylXcXJstNAB;}" fullword ascii
    $s8  = "function VTznnNIky(ZfFGLmfgppfdm) {var lEvgmmSKjD = ycHFNDoqPBVWvzNdGgHKpjrX.join(ZppHkF[0]);var LeEeFlAoDVj, FQPwKmekIinX, jdkv" ascii
    $s9  = "function HTZMIT(VCCZmrOAcTIGqpmox,dKCOA){return VCCZmrOAcTIGqpmox.indexOf(dKCOA);}" fullword ascii
    $s10 = "function ZiyUYigFG(JWmUcJzL,pwjWCWkBuaURX){return String.fromCharCode(JWmUcJzL,pwjWCWkBuaURX);}" fullword ascii
    $s11 = "function PW(JIUXVzZAv){return String.fromCharCode(JIUXVzZAv);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}