rule sig_20160503_7c8b364852a231855dbee050c483855a {
  meta:
    description = "datamaliciousorder - file 20160503_7c8b364852a231855dbee050c483855a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a2f0ce0cf9b21f386d7da0f04eb43f7ecda4c1d1c202e1b07d8345cec42f6ba"

  strings:
    $s1  = "eval((function(){var p=[94,86,72,81,60,90,76,88,79,65,80,87,82,89,85,75,70,71,74,66];var h=[];for(var j=0;j<p.length;j++)h[p[j]]" ascii
    $s2  = "ar j=0;j<g.length;j++)d=d.split(u+a.charAt(j)).join(String.fromCharCode(g[j]));return d.split(u+'!').join(u);})('function e@vj@m" ascii
    $s3  = "eval((function(){var p=[94,86,72,81,60,90,76,88,79,65,80,87,82,89,85,75,70,71,74,66];var h=[];for(var j=0;j<p.length;j++)h[p[j]]" ascii
    $s4  = "break}^p~t@mpu@m@z@h~@j@oT@p@ing~8922,9401,3~}function ~;breV!;;~]^`@~k@w@rlrg@h~ase 0^r~);^d1~Tt@xr@m@jN~\"^`~=\"heagc@q~;retur" ascii
    $s5  = "dj@sM){c^[xDvqI@ng=58486^{xDvqI@ngV,){}^5if(hy@o@u=^s){^A^jif(ztf=^s^}break}^{ztfV(heM@z\"^g@ph@ye@v=\"Eepi@j@xE\"}^p@wtkzi=\"x@" ascii
    $s6  = "@n@object,(3223,4617,3274,2)][1^YqoDio^Wf^mdfegg^gy@zzgh=mcd@ujd(^q6V(@prgudT\"){}^pyzsd=83878^{yzsd=^<@yven=83436}^{6^:Sx@v@h^h" ascii
    $s7  = "(k+1)-32;i=k;k++;}else if(l==96){b=94*(p.length-32+y.charCodeAt(k+1))+y.charCodeAt(k+2)-32;i=k;k+=2;}else{continue;}if(s==null)s" ascii
    $s8  = "t@v=@pEitIyE.length;while(V @k@t@rM@yqy@t@v-(144^C)^g@p@w@o@q=^;^%^#^pEx@om@wl^n^B^pNc@q@z@rpjj^&Ex@om@wl^fjit@r@s^&V +(144^C)^f" ascii
    $s9  = "+^B)==^;^%^#^qD@nE==@p@w@o@q^g@tyCoI@m^n^B^p@sTeN@mNi^n(2^fhNTgga^&@sTeN@mNi);^U^&@tyCoI@m)+hNTgga}^p@hw@re@u=\"uxo@j\"^thw@re@u" ascii
    $s10 = "]()}}catch(@y@wiN){}~eak;case ^jvar ~ak;case true:if(6==~^%3~3,1288,4306,8939,0)~eak;case true^r~5,849,8222,7868,11~=gsjpoTm(@pE" ascii
    $s11 = "~(^f@~0:if(7==~(^g~switch(~x@wE=\"f~)^p~){^z~=^v~^s;~^v:~{case ~bnn@sE~s@l@o(~=V +~i^s~;^z~)^{~:^z~=true~^{@~\":var~false~05204~" ascii
    $s12 = "@uvmz@q\")~^d3){case ~ @vwim=48840;br~^40~[^>~^M1:~^? ~ @jhkj=29940};~a@nz@i\"^{x@w~))+CcSsxp@j((~===true^g~(5768,8646,10~==fals" ascii
    $s13 = "case~yj=\"kN@xD@n\"}~);@nw@sMnua@p~^tpvqct@mi~s@zDp=\"jySte\"~^p@pvqct@m~;break;case ~@i@j@zS@q@jD~^V9~975,7400,611~^W@~))+qT@jv" ascii
    $s14 = "g~break;case 0:~N@h@jgsg@r(\"0~\"yef@tk\"){var~^v;break};~}^M~(7230,5686,1)~4,8315,1045,2~@wtb=34510;br~^P6~6,9165,3302,3~witch(" ascii
    $s15 = "w\"^twtkzi^<sv@w@z^h^A285^rI@hI=\"@t@hvwV&eak}}try{uCIca(1,^v,^v,^v);@qmjpu(513,0,0);e@vj@mg(true,true,true,1^fm@l@lCsui=([(8827" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}