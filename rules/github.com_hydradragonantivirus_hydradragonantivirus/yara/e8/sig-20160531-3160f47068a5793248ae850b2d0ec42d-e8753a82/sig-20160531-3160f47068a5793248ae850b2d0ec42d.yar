rule sig_20160531_3160f47068a5793248ae850b2d0ec42d {
  meta:
    description = "datamaliciousorder - file 20160531_3160f47068a5793248ae850b2d0ec42d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a74ddb31dc35002124d8d8e24544b831e3435588feb3072892fd034fc2ab9a9"

  strings:
    $s1  = "function TFWyEAMdzWAJkhYk(ggMlFfWDUiuFsGYHtKf,OYGeEWYofCShDxhX){return ggMlFfWDUiuFsGYHtKf.charAt(OYGeEWYofCShDxhX);}" fullword ascii
    $s2  = "(HlxEYEcnlLlOr,0x1,0x0)}function XolfwHCrfCgUk(bCqcDLYS,tWWMh,fuIhASr){var DgcUJEQ=bCqcDLYS.createtextfile(tWWMh,true);DgcUJEQ.W" ascii
    $s3  = "(HlxEYEcnlLlOr,0x1,0x0)}function XolfwHCrfCgUk(bCqcDLYS,tWWMh,fuIhASr){var DgcUJEQ=bCqcDLYS.createtextfile(tWWMh,true);DgcUJEQ.W" ascii
    $s4  = "var juRqcglHw=function(){return WScript.CreateObject(kTQyfjpMxCAxBTyLoJeYv[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s5  = "function hmYzTmbCU(QfrxrTAt,HlxEYEcnlLlOr) {var aFkppXnU=[kTQyfjpMxCAxBTyLoJeYv[15]];QfrxrTAt[aFkppXnU[0]]" fullword ascii
    $s6  = "function vazdApOXFOs(gnYxrEXctck,WaPDNv,OmMaGmorPhugBOWGILDVexS){return String.fromCharCode(gnYxrEXctck,WaPDNv,OmMaGmorPhugBOWGI" ascii
    $s7  = "sczT == 64) dCGCcjLhrCeyBbNKBsyL += pbWOOOnjRJCR(wymuFyz, feiuGpaydUuapj);else dCGCcjLhrCeyBbNKBsyL += vazdApOXFOs(wymuFyz, feiu" ascii
    $s8  = "GpaydUuapj, PkklPQMuyFWgmBio);} while (iCHRIQYFFd < VmMNNJtmSQueI.length);return dCGCcjLhrCeyBbNKBsyL;}" fullword ascii
    $s9  = "function XpjkvUHFpsIkqjqfedvzpG(cPUDQBEFkwugAHkKMV,ORpBJMvUrayAtXibbtlQkY){return cPUDQBEFkwugAHkKMV.indexOf(ORpBJMvUrayAtXibbtl" ascii
    $s10 = "function pbWOOOnjRJCR(HCsUvUVwtEy,UrJYcNyigvIuSkIte){return String.fromCharCode(HCsUvUVwtEy,UrJYcNyigvIuSkIte);}" fullword ascii
    $s11 = "function r(vOlONxkT){return String.fromCharCode(vOlONxkT);}" fullword ascii
    $s12 = "or(HtMxKLaONSx=0;HtMxKLaONSx<mglPvmc.length;HtMxKLaONSx++) {WQLSuirlwim+=fRuHDImhmaq[mglPvmc[HtMxKLaONSx]];}return WQLSuirlwim.s" ascii
    $s13 = ">> 8 & 0xff;PkklPQMuyFWgmBio = UOgqMpHhMhGgVU & 0xff;if (LSwGUNMhCX == 64) dCGCcjLhrCeyBbNKBsyL += r(wymuFyz);else if (JIWMpskxI" ascii
    $s14 = "function vazdApOXFOs(gnYxrEXctck,WaPDNv,OmMaGmorPhugBOWGILDVexS){return String.fromCharCode(gnYxrEXctck,WaPDNv,OmMaGmorPhugBOWGI" ascii
    $s15 = "function EhOGZRT(){return juRqcglHw.ExpandEnvironmentStrings(HDQAWzeqYs())}" fullword ascii
    $s16 = "function XpjkvUHFpsIkqjqfedvzpG(cPUDQBEFkwugAHkKMV,ORpBJMvUrayAtXibbtlQkY){return cPUDQBEFkwugAHkKMV.indexOf(ORpBJMvUrayAtXibbtl" ascii
    $s17 = "function HDQAWzeqYs(){return GRUGbgfrWcQXsp(kTQyfjpMxCAxBTyLoJeYv[9],[1,5,7],kTQyfjpMxCAxBTyLoJeYv[10]);}" fullword ascii
    $s18 = "function GRUGbgfrWcQXsp(SwhoA,mglPvmc,vDMxuwhTZvr){fRuHDImhmaq=SwhoA.split(vDMxuwhTZvr);WQLSuirlwim = kTQyfjpMxCAxBTyLoJeYv[0];f" ascii
    $s19 = "function FLgDFvGmsmnJgk(){return GRUGbgfrWcQXsp(kTQyfjpMxCAxBTyLoJeYv[11],[2,4,8,10],kTQyfjpMxCAxBTyLoJeYv[12]);}" fullword ascii
    $s20 = "function gUACVvOefS(){return GRUGbgfrWcQXsp(kTQyfjpMxCAxBTyLoJeYv[13],[0,3,6],kTQyfjpMxCAxBTyLoJeYv[14]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}