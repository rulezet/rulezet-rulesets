rule sig_20160503_9e1b23a6262cbfc8871a44d652585c39 {
  meta:
    description = "datamaliciousorder - file 20160503_9e1b23a6262cbfc8871a44d652585c39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a110d466b8a74b2e5f1f18066be2aa6cd3848e7da9bef9d9e5ea4762cdf34a5d"

  strings:
    $s1  = "ar m=0;m<x.length;m++)u=u.split(f+i.charAt(m)).join(String.fromCharCode(x[m]));return u.split(f+'!').join(f);})('function xirDln" ascii
    $s2  = "eval((function(){var d=[90,82,80,76,81,71,70,86,72,75,65,94,88,60,74,66,85,79,87,89];var w=[];for(var m=0;m<d.length;m++)w[d[m]]" ascii
    $s3  = "(t+1)-32;g=t;t++;}else if(k==96){r=94*(d.length-32+s.charCodeAt(t+1))+s.charCodeAt(t+2)-32;g=t;t+=2;}else{continue;}if(v==null)v" ascii
    $s4  = "055R)79049046033022011012\")Zkktss@xD@h=ZJ37031007\"Zl4Zudb@yuk\"R(bZC13042Z{29Zwktss@xD@h,oe@ljN@m,false);sZBZ*otZAZ9Z1reZSZ/Z," ascii
    $s5  = "292:Zp@svTv=\"@kMuz@ySi\"Z>if(4ZWZpv@w@g@y=42627};break}ZkjDN@msDrZmZd v@weEh@z=@Z\\')ZkZj1=(v@weEh@z=Z=ZlZj1&&Zj2Zb@may@sdZ_ZVZ" ascii
    $s6  = "lx=Tea>(8000,846,1513,5302,2251,261,6187,2378,110,4085,4156,5Zl@iju@vcS@lx){[(9R\"7578,882Zt,qk@v][(9R\"7578,882Zt]()}}else {sR," ascii
    $s7  = "eval((function(){var d=[90,82,80,76,81,71,70,86,72,75,65,94,88,60,74,66,85,79,87,89];var w=[];for(var m=0;m<d.length;m++)w[d[m]]" ascii
    $s8  = "iTp()](pgTxeZl7Zf){}Zcyp@nZeif(@yp@n==236R(Z^7Za1R%5==\"kuwCT\"){}Z>Zphc@l@s=50315Z>ZpnTw@p@xu=\"Ig@g@w@z\";break};;ZYcnvZMT@yjl" ascii
    $s9  = "neg=hniTy.length;while(@R&@tm@yN@hneg-ZVZ+Z)Z#ZbsopiZ=ZkjR+Z_R\\'Z!ZkM@j@x@z=@ZDjR+)ZkCe@hS@s@n=@Z\\'+ZVZ+Z)Z#)Zci@ukMxba@v=@Z" ascii
    $s10 = "~ak;case \"T~@uCfh@yf()~\"ZY~(2502,644~==false){~@xaDagz@h~;return ~he@zEqqp~1:ZpCD~()Zk~(Zb~switch(~=@R&+~=false;~){case ~){Zp~" ascii
    $s11 = "~r t@snw@zhZeb~eak;case 552:Zp~m@l@n=\"pfd@u@gt\";~se;break}Zku@u~M=55046;break;cas~@qI@o\":Zp@ilmx@~tZAo~ot@hC=Zf){va~))+@ZQ(~@" ascii
    $s12 = "R )}}catch(TvlMl){}~){}Zcusg=88687;~6,2734,7548,5474,1)~i@p@iSlZF~5,9964,7858,9650,2)~Z)5~alse){}ZG~reak;case true:Zp~ZD@wNgl~Z+" ascii
    $s13 = "[ZJ~;break;case ~ZM@~))+@Zh(~@z@q@z@n(\"0~se false:va~kt=33983;br~}function ~x@vbfq@qx(~R(break}~@wrCNS@x@z~yw@s@go@p(~w@h@vE@uS" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}