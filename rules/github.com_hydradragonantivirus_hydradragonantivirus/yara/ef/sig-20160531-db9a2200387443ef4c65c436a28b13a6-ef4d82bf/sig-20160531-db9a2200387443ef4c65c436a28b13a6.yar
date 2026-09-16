rule sig_20160531_db9a2200387443ef4c65c436a28b13a6 {
  meta:
    description = "datamaliciousorder - file 20160531_db9a2200387443ef4c65c436a28b13a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d77e06a62313759c1dc90c82130977e8eff34b46835c71bab2cdd86bce49ccc"

  strings:
    $s1  = "var QUEUZaozGClWQi=function(){return WScript.CreateObject(GcQkMeULKjXidGhc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function HFpjhBZbFFoXzDDKrdydbHU(MLjTXTr,efxkVZKuabvMuHlOacsOT){return MLjTXTr.charAt(efxkVZKuabvMuHlOacsOT);}" fullword ascii
    $s3  = "function JMHKi(EJXWNNxo,LLesELoOtZ,dFWge){uoMdItxQHamv=EJXWNNxo.split(dFWge);duojllmGKOs = GcQkMeULKjXidGhc[0];for(QQRmBgRg=0;QQ" ascii
    $s4  = "function NOUzapnFOx(){return JMHKi(GcQkMeULKjXidGhc[11],[2,4,8,10],GcQkMeULKjXidGhc[12]);}" fullword ascii
    $s5  = "function NqgdgfREomZPPZIXwLhZVR(ehXwU,yslNErAOeknGXPAUF){return String.fromCharCode(ehXwU,yslNErAOeknGXPAUF);}" fullword ascii
    $s6  = "function gNDfeiekNENqt(VBWSwHVGDYfGH) {var MgDskEvohi = jSxGJfnylQPcyOFj.join(GcQkMeULKjXidGhc[7]);var NspAAQeAhRhXZtNmBZpUy, fA" ascii
    $s7  = "function rIKhattwwQvGgECJdZsjbnzO(EUuLvJvjPqpgtKsIr,htZLUOb){return EUuLvJvjPqpgtKsIr.indexOf(htZLUOb);}" fullword ascii
    $s8  = "= hS(NspAAQeAhRhXZtNmBZpUy);else if (LJuWy == 64) hSTdUMGCBgKdUgCHMg += NqgdgfREomZPPZIXwLhZVR(NspAAQeAhRhXZtNmBZpUy, fAMPQFdORc" ascii
    $s9  = "diDriadgP < VBWSwHVGDYfGH.length);return hSTdUMGCBgKdUgCHMg;}" fullword ascii
    $s10 = "(HquMSqVr,0x1,0x0)}function aguPXl(ftyoAIJe,bZewaoNlNT,NUTEAhNk){var oFoisizihyMX=ftyoAIJe.createtextfile(bZewaoNlNT,true);oFois" ascii
    $s11 = "function gNDfeiekNENqt(VBWSwHVGDYfGH) {var MgDskEvohi = jSxGJfnylQPcyOFj.join(GcQkMeULKjXidGhc[7]);var NspAAQeAhRhXZtNmBZpUy, fA" ascii
    $s12 = "function loIpQIHiWrdiwK(){return JMHKi(GcQkMeULKjXidGhc[9],[1,5,7],GcQkMeULKjXidGhc[10]);}" fullword ascii
    $s13 = "function ebfbSnuBkl(){return JMHKi(GcQkMeULKjXidGhc[13],[0,3,6],GcQkMeULKjXidGhc[14]);}" fullword ascii
    $s14 = "function SJHpyjmp(){return QUEUZaozGClWQi.ExpandEnvironmentStrings(loIpQIHiWrdiwK())}" fullword ascii
    $s15 = "var TmmaRmX=function(){return new ActiveXObject(GcQkMeULKjXidGhc[1]);}();" fullword ascii
    $s16 = "function RkSuxbP(ciNSDUviQht,HquMSqVr) {var RIsfCxpUKJ=[GcQkMeULKjXidGhc[15]];ciNSDUviQht[RIsfCxpUKJ[0]]" fullword ascii
    $s17 = "RmBgRg<LLesELoOtZ.length;QQRmBgRg++) {duojllmGKOs+=uoMdItxQHamv[LLesELoOtZ[QQRmBgRg]];}return duojllmGKOs.substring(3,duojllmGKO" ascii
    $s18 = "function hS(FnFxeVngusZszLYJ){return String.fromCharCode(FnFxeVngusZszLYJ);}" fullword ascii
    $s19 = "function haCMrJyWsv(cfqIQKjuFIppMGhY,bygJu,ONjhWVqufwFS){return String.fromCharCode(cfqIQKjuFIppMGhY,bygJu,ONjhWVqufwFS);}" fullword ascii
    $s20 = "(HquMSqVr,0x1,0x0)}function aguPXl(ftyoAIJe,bZewaoNlNT,NUTEAhNk){var oFoisizihyMX=ftyoAIJe.createtextfile(bZewaoNlNT,true);oFois" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}