rule sig_20160527_96ec5d7a2c344efcee28837d0b7454c1 {
  meta:
    description = "datamaliciousorder - file 20160527_96ec5d7a2c344efcee28837d0b7454c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69f6f5cd6edbfdccf4be3b93bdf5372b38dcb3f34f78e4ae600f8f1473c8812c"

  strings:
    $s1  = "function WoVkxTZLdWF() {return WScript;}function AzlSaKdW(){return uudhdQFWgLUYwM.ExpandEnvironmentStrings(KMYwCevmdtW())}" fullword ascii
    $s2  = "function BQwRglMFwon(gPOhg,dixobRLPWUDbSyxJst){return gPOhg.charAt(dixobRLPWUDbSyxJst);}" fullword ascii
    $s3  = "function CoVJiKKss(hHVBeUdyGiI,Fqgrz) {var COIrMBKzgwiNqf=[mcWLhF[15]];hHVBeUdyGiI[COIrMBKzgwiNqf[0]](Fqgrz,0x1,0x0)}" fullword ascii
    $s4  = "function rHKImwFeMUJPIGr(BXNimRTWqsvqAgtX,lexOwXxLZjKAdXZmZxzcegGq,ObwNsRhbeR){return String.fromCharCode(BXNimRTWqsvqAgtX,lexOw" ascii
    $s5  = " oxBxKApdkOxAwlIm += Dm(RhvljxDjvOPHUgntffv);else if (dlSmbzjeWSU == 64) oxBxKApdkOxAwlIm += uzYKRAjjmjoxzSeWxCBMn(RhvljxDjvOPHU" ascii
    $s6  = "function QPyWGcNAblULw(GIwwjehMdlQs,UNGcqwAf,QkVJNkTQSE){ObKRfpqNFDw=GIwwjehMdlQs.split(QkVJNkTQSE);MFoIk = mcWLhF[14];for(XqJtE" ascii
    $s7  = "function Dm(zRdEwOfGrZVft){return String.fromCharCode(zRdEwOfGrZVft);}" fullword ascii
    $s8  = "function QPyWGcNAblULw(GIwwjehMdlQs,UNGcqwAf,QkVJNkTQSE){ObKRfpqNFDw=GIwwjehMdlQs.split(QkVJNkTQSE);MFoIk = mcWLhF[14];for(XqJtE" ascii
    $s9  = "var uudhdQFWgLUYwM=function(){return WoVkxTZLdWF().CreateObject(mcWLhF[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function rHKImwFeMUJPIGr(BXNimRTWqsvqAgtX,lexOwXxLZjKAdXZmZxzcegGq,ObwNsRhbeR){return String.fromCharCode(BXNimRTWqsvqAgtX,lexOw" ascii
    $s11 = "function ozFvcfK(YnsXnpnsBrlIw) {var pCPXAyGvCQwYiVrTvuAiloZ = qhWdnDdSfZS.join(mcWLhF[6]);var RhvljxDjvOPHUgntffv, rzXRTgvWuDHU" ascii
    $s12 = "var hnlOk = NwcDBFUHejf.createtextfile(uudhdQFWgLUYwM.ExpandEnvironmentStrings(mcWLhF[2]+mcWLhF[3])+String.fromCharCode(92)+mcWL" ascii
    $s13 = "function uzYKRAjjmjoxzSeWxCBMn(tKWHJHRsHOyP,GRuUyZB){return String.fromCharCode(tKWHJHRsHOyP,GRuUyZB);}" fullword ascii
    $s14 = "e (NlaIMQnGYXMfxLGlIYLvKXoi < YnsXnpnsBrlIw.length);return oxBxKApdkOxAwlIm;}" fullword ascii
    $s15 = "function YnzvNJPErbtvaFnZDPYbYv(PWQDVMNXrnfQDRNcKHpyh,EjsNeRoHeKKDbZi){return PWQDVMNXrnfQDRNcKHpyh.indexOf(EjsNeRoHeKKDbZi);}" fullword ascii
    $s16 = "gntffv, rzXRTgvWuDHULWmru);else oxBxKApdkOxAwlIm += rHKImwFeMUJPIGr(RhvljxDjvOPHUgntffv, rzXRTgvWuDHULWmru, PPQiDHqhgxVe);} whil" ascii
    $s17 = "function KMYwCevmdtW(){return QPyWGcNAblULw(mcWLhF[8],[1,5,7],mcWLhF[9]);}" fullword ascii
    $s18 = "function ozFvcfK(YnsXnpnsBrlIw) {var pCPXAyGvCQwYiVrTvuAiloZ = qhWdnDdSfZS.join(mcWLhF[6]);var RhvljxDjvOPHUgntffv, rzXRTgvWuDHU" ascii
    $s19 = "function VxgGk(){return QPyWGcNAblULw(mcWLhF[12],[0,3,6],mcWLhF[13]);}" fullword ascii
    $s20 = "var NwcDBFUHejf=function(){return new ActiveXObject(mcWLhF[0]);}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}