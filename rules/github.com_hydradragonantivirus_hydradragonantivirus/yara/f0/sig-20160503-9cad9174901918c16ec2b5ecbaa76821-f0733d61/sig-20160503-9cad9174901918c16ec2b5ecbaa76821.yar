rule sig_20160503_9cad9174901918c16ec2b5ecbaa76821 {
  meta:
    description = "datamaliciousorder - file 20160503_9cad9174901918c16ec2b5ecbaa76821.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7137e5acd811ea72d86c6e79ffdbb59e57094fe0db8cb44aedc6a1f66482c7ff"

  strings:
    $s1  = "ar g=0;g<b.length;g++)i=i.split(a+z.charAt(g)).join(String.fromCharCode(b[g]));return i.split(a+'!').join(a);})('function Igw@pz" ascii
    $s2  = "eval((function(){var h=[74,65,71,86,79,80,94,75,60,82,70,72,85,66,89,81,88,90,87,76];var c=[];for(var g=0;g<h.length;g++)c[h[g]]" ascii
    $s3  = "(x+1)-32;w=x;x++;}else if(d==96){f=94*(h.length-32+r.charCodeAt(x+1))+r.charCodeAt(x+2)-32;w=x;x+=2;}else{continue;}if(t==null)t" ascii
    $s4  = "46,9529,14A.03,5661,0))};@njs(@nEk,@A\"s@p)JAdhhp@we(@voSNm,MndD,E@gI){switch(A0)J?Jw@x@n@z@t@l@z@y=J%JFq@l@jx@wC=81045;JjJVJs}t" ascii
    $s5  = ";return ~(Jd@~J`@~;switch(~3372,852~0,3056,7~Czvot@iy~=1Jd~@iDb@lN(~jqwN@q((~(Jf~=Js;~@xgl@kl~z@u@n@h~){Jw~Jo@~)Jo~fTt@ue~Js)~zS" ascii
    $s6  = "eval((function(){var h=[74,65,71,86,79,80,94,75,60,82,70,72,85,66,89,81,88,90,87,76];var c=[];for(var g=0;g<h.length;g++)c[h[g]]" ascii
    $s7  = "thJoJbJJJ JYJhJ?Jw@z@zvy@g=85800J8JFvmaD=55742JxvmaDJEJ50Jq@i@ijc=JsJKJwA6\"\"Jet@ifv=gC@l.length;while(Jb@o@t@ifv-(JZJ-J)JdTrbs" ascii
    $s8  = "(9698,1757,1822,5JrpuEa@s@l@h){[(5853,7721,6523,1081,1),@v@yj][(5853,7721,6523,1081,1)]()}}catch(ye@tN){}~4,8177,7546,9522,0)~J$" ascii
    $s9  = "J2J9A\"kJLJ,\"JlJQJ%JIJcJPJ3J@J;@qMJ7J3JtJ1J/1JeuJy@h=J^qEgjJuJ(00029038035033J}JgJB05J{60039043A757035A&56011054\")])JY1){case " ascii
    $s10 = "eak;case ~=trueJd@~J@(~(6===0Jd~JA@~))+J_~zN@p@r@xMan~{case A0:~i@jif@s\":if~}function ~[D@w@vi(\"0~=D@w@vi(\"0~))+@Ji~===Jh{~fa" ascii
    $s11 = "@lto@vb=@tpDbd(JbJfodup=@y@sxEy(@r@lto@vb,r@vqlCafpJfJ>=N@rCJy(\"@yo@k@yD@l@g@q@u\",odup)Jer@zo@j@h@ux=39893JY6){case 0J|4==\"E@" ascii
    $s12 = "z@g=32111JY1)J?if(5JEJw@hqsvrEc=11946J51JqtuDdf=21236;JjJY6){case \"uS@w@ul\"Jquogq@l=\"Il@knn\"J81J|2=J]z@tnp=\"@l@gC@ya\"J5JF@" ascii
    $s13 = "l~}JY4){case ~8,1448,4668,8980~J1T~TaJabreak};~k;case \"@Jtz~zyhm@r\"Jquad~@j@qe@l@j@h@w=~J8\"@~J7;~}J8~==0Jd@qMi~i@gr@h=58774}~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}