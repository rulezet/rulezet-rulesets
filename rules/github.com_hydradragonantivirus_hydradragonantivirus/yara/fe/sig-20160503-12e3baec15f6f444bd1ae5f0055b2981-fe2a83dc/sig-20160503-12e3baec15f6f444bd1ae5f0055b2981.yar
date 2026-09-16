rule sig_20160503_12e3baec15f6f444bd1ae5f0055b2981 {
  meta:
    description = "datamaliciousorder - file 20160503_12e3baec15f6f444bd1ae5f0055b2981.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf7fb0b52c2c4a96697599e7c353fbdc53d3fe61c29340da943f21f044e4a6b5"

  strings:
    $s1  = "eval((function(){var v=[90,81,89,72,66,85,80,82,88,65,71,79,76,94,86,75,70,60,74,87];var z=[];for(var m=0;m<v.length;m++)z[v[m]]" ascii
    $s2  = "ar m=0;m<k.length;m++)n=n.split(i+r.charAt(m)).join(String.fromCharCode(k[m]));return n.split(i+'!').join(i);})('function Q2iCbs" ascii
    $s3  = "]\"\"Z_yiqc@r@gh=@oyQ,@s@zbS.length;while(ZU@x@yiqc@r@gh-(928,Z+Z^@g@ols=Z&Z_zyhppMaZEZdZ(Z%Z\"Zguky@iwp@l@nZbZ @zyhppMa)Z_y@kaa" ascii
    $s4  = "eval((function(){var v=[90,81,89,72,66,85,80,82,88,65,71,79,76,94,86,75,70,60,74,87];var z=[];for(var m=0;m<v.length;m++)z[v[m]]" ascii
    $s5  = ",SInh@r,@rN@w@z@o@h,ljynNd,CrQ ]ZRxcTomqh[f@hse@pS@sw]ZBkbk@h@uu(Z^Dp@vjdx@ma=ZCZ&)+ZCZ\\\\Z(Z%Z\")+ZCZoZ+Z>Z8Z2Z-)+ZC(611Z}51Q:" ascii
    $s6  = "s(kTdZ^D@vj@soa=31355ZqD@vj@soa===1){}Z_hm@nS=\"xvyiSZfhm@nS==731){}ZR1}try{@udyn@p@p(\"Nv@qD@hN\")ZqzEhs(331)!ZX@jt@ud=12918}el" ascii
    $s7  = "(b+1)-32;l=b;b++;}else if(h==96){a=94*(v.length-32+s.charCodeAt(b+1))+s.charCodeAt(b+2)-32;l=b;b+=2;}else{continue;}if(y==null)y" ascii
    $s8  = "46,4968,7100,1)~eak;case Zcvar ~Z(,~,2356,583,4477,291~(356,7047,2639,0)~=trueZ?~74,1608,6759,1218~break;case 0Zh~==1){Zveak;cas" ascii
    $s9  = "e~6963,7521,8552,2)~Z22~2412,9067,6017,3)~hj@gf@pxZK~eak;case Q#:va~ZT1){case ~ar ch@ljDZ[~8,2116,597,4549,~ZSswitch(~)Z9~){if(4" ascii
    $s10 = "==408Q\"~);DpNaZK~ZS;;var ~(7041,3346,527~Z>(~)Zq5==1){};v~zi@s@y@lok@w10~}Z?~ZOvar ~)+ZC~;break;case ~))ZQ(~ZBl~ZF@~y@q@sf@pkw(" ascii
    $s11 = "ak};~;swiQ1~@s@yIkzD~(Z^@~=Zl){~=1Z^~()Zg~){case ~Za;~(Zd~@n@uvC=~){Zr~Zg@~1Zh~=false~=@lrbd~false:~7707,2~)];var~Zk@~;Zr~:Zr~\"" ascii
    $s12 = "{case Q#:~=ZU+(~}function ~DT@g@l@j()~Tn@q@kt@qI~ZU);~\"ZR~[@r@wN(\"0~)ZR~=@r@wN(\"0~Zl;if(~=Za){~=@ip@z@v(~+@sI@iwj(~;return ~;" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}