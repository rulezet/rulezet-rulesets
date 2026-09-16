rule sig_20160503_1fe17b5324f6d9bd934d9ffb20c9541f {
  meta:
    description = "datamaliciousorder - file 20160503_1fe17b5324f6d9bd934d9ffb20c9541f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7f8b34365a8aea5ac39e4ed8aaadfd67d6f45252e757e8defc67f0890c6c289"

  strings:
    $s1  = "ar h=0;h<e.length;h++)b=b.split(s+w.charAt(h)).join(String.fromCharCode(e[h]));return b.split(s+'!').join(s);})('function @x@u@q" ascii
    $s2  = "eval((function(){var t=[82,90,94,80,88,70,60,65,87,81,66,86,89,71,72,74,85,75,76,79];var j=[];for(var h=0;h<t.length;h++)j[t[h]]" ascii
    $s3  = "kTj@p@l@s@t){[(7289,7Z#3504,3026,9Ry28,7875,6626,5492,7666,1),lzzSj][(7289,7Z#3504,3026,9Ry28,7875,6626,5492,7666,1)]()}}else {h" ascii
    $s4  = "n@g@ob,gmqm,false);RHR<R#RnR9R01ROR:R@R1RLRAR#RiR=R>R6R( @R?R7R3R/Rm;3;t@oCRB27Rw1Rz\")]Ro laan@xRD59Z!2206305206202403001Rw0230" ascii
    $s5  = "tion ~;Rm;;;~I@y@ptz@qy~207,3386,2~\"R]~))+u@vo((~3516,4142~Rr;if(~;return ~;switch(~(Rk@~@zDmSn@x~;;Rq@~glcrnd()~Rj@x~Rl){~yz@t" ascii
    $s6  = "w(j@xev){switch(falseRg1:Rupekn=25323Rvpekn===\"@xnicegCq\"Rj@v@ro@n=\"f@v@lfd@g\"RC71:RuipT@gICN=\"dqbN@og@p\";RmR^1){R4cN@n=62" ascii
    $s7  = "eval((function(){var t=[82,90,94,80,88,70,60,65,87,81,66,86,89,71,72,74,85,75,76,79];var j=[];for(var h=0;h<t.length;h++)j[t[h]]" ascii
    $s8  = "W][M@zb]R]x@gkeERUoCy(fmSzS@v@x){switch(6Rg\"hy@wq@o@w@r\"Rx1==33RcexM@tt@w=55960RC\"Dx@slv\"Rx5==0){RC395Rx1===1RjwhCey=\"fCTtT" ascii
    $s9  = "E@wie=\"hod@rD@vqpm@v@pxq@kx\".lengthRqR`=(55R RqkTSi=\"TsgN@otb\";;RqRp=\"\"RqfkDvtq=@vq@wp.length;while(R`@mfkDvtq-(3516,4142R" ascii
    $s10 = "(c+1)-32;q=c;c++;}else if(p==96){n=94*(t.length-32+z.charCodeAt(c+1))+z.charCodeAt(c+2)-32;q=c;c+=2;}else{continue;}if(v==null)v" ascii
    $s11 = "R|R-Rk@zntN=12184R^4Rg1:RuCk@ut=69272RvCk@ut==\"dD@od@osvzR00:Ru@qn@h@u=32056Rsqn@h@u==\"@u@p@qkM\"RjDdD@hRr}RK@txiRrRajit102=(R" ascii
    $s12 = "f@t@y(true)}}catch(@hrvt@gM){}~05,2616,4263,312,0)~R%6~6Rq@he@z@h=5594;~=falseRhcase ~R\\'a~ar w@ko@xv@pD=6285~f(5==Rdvar ~@nm=" ascii
    $s13 = "vi@sTCb\"};v~Rhcase 1:var~@huuRB~6127,2881,8274,1)~,815,4633,3107,2)~Rhcase true:~k(@vq@wp,R`~R3E~EqkEh@s@s=86766};~\"){RC~;brea" ascii
    $s14 = "@xM~(Rj~){case ~;break;~140:var~){Ru~)Rq~=false~break}~false:~();var~s@uvzT~;Ru~=true~Rv@~6927,~var ~;if(~0100~:if(~03,7~0050~\"" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}