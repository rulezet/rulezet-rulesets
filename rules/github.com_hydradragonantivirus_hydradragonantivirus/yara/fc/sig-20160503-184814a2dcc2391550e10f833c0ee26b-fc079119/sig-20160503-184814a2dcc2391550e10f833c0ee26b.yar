rule sig_20160503_184814a2dcc2391550e10f833c0ee26b {
  meta:
    description = "datamaliciousorder - file 20160503_184814a2dcc2391550e10f833c0ee26b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd4998068cc838ba48ba28c80d23c6de92b06a6a0d030c41e4a46c27c8f345da"

  strings:
    $s1  = "eval((function(){var a=[66,65,72,82,88,87,89,81,71,74,90,76,94,60,86,70,85,80,75,79];var h=[];for(var v=0;v<a.length;v++)h[a[v]]" ascii
    $s2  = "ar v=0;v<y.length;v++)p=p.split(k+n.charAt(v)).join(String.fromCharCode(y[v]));return p.split(k+'!').join(k);})('function mIsj(@" ascii
    $s3  = "\";B(@miq@mn@x@h=BlBIBwo@r@upT@v@q@kBZ@mabi@yBDB6B, @B.brB BuB0rB B?B/B ll@B5;Bjse@kudN=B[BG2Bt28062006022021B|45038034A66306101" ascii
    $s4  = "pC@l~;break}~)]Bj~=Bl;~){Bw~)Bj~();var~Bl)~ouD@jz~yv@l@z~(2A$~;Bw~:Bw~false~=Bz~)Bv~\"Bv~==0){~==fal~70190~;o@r@~0A3~@q@jp~;if(~" ascii
    $s5  = "f(b@pab==1){};brB S@xvISIn=13729B@415Bkjsr@klt=\"Dpyoq@q@l\";B(Dd@jm@lBmBIBwv@qjfpbDcBZh@A%nq@ypB]mabi@yBF18029039A=520930370530" ascii
    $s6  = "eval((function(){var a=[66,65,72,82,88,87,89,81,71,74,90,76,94,60,86,70,85,80,75,79];var h=[];for(var v=0;v<a.length;v++)h[a[v]]" ascii
    $s7  = "(u+1)-32;m=u;u++;}else if(d==96){s=94*(a.length-32+t.charCodeAt(u+1))+t.charCodeAt(u+2)-32;m=u;u+=2;}else{continue;}if(g==null)g" ascii
    $s8  = "===1BcdD@xCtBm}Bj@rak@pTe@k=35567;;BjBg=\"\"Bjldvlp=tfv.length;while(Bh@tldvlp-(2A$B+BceSkB<B!Bjd@q@z@v@lBXBAB)B#Bjc@n@lrprnBPd@" ascii
    $s9  = " falseBk~43,538,5563,5205,0)~3B)8~8,6599,3327,6786,1)~upT@v@q@kBG~B\\'v~Bwfq@p@yE=55379;~ar @ra@x@n=14460;~break;case 1Bk~093,22" ascii
    $s10 = ",4082,5675,4587,8955,2063,777,5889,6787,5BnS@r@wn){[(92A9358,8914,1),@g@p@u@xcx@z][(92A9358,8914,1)]()}}catch(wfmT@q){}~eak;case" ascii
    $s11 = "4,9315,215~se){B>~5808,6348,7916,2)~6B^false:var~B66~x@zn@k@pogBb~(cgEa===718){};br~gxIE=\"h@l@vwMo\";b~{case trueBk@~009,4445,1" ascii
    $s12 = "m){};~\"BS~]BS~zT@q@ut()~=bNg(tfv,~B^0:~BW1~;return ~(B]~))+B{(~B\\\\@~;switch(~=Bh+~{switch(~=tC@m@w(~dCTjS@wM~(Bc~Bd@~){case ~" ascii
    $s13 = "gEa=71988;if~;break;case ~(8754,8901,3~r@giE@xIrm10~BE@~Bdh@osx~}function ~=@mtr@k(\"0~[@mtr@k(\"0~c@w@zhsi()~B`;;;~===Bf{~)BS@~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}