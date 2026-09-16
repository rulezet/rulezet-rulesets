rule sig_20160503_854348e6e47b23cf7d159c76945548e2 {
  meta:
    description = "datamaliciousorder - file 20160503_854348e6e47b23cf7d159c76945548e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b1cfe008cc0cc34aaa910bd8dc0b3c662a11c74e0afdb4aeca06568b54d82a2"

  strings:
    $s1  = "nC@u=55021}W(yc@mTcp(1,1,1)!W\"OgtnC@u=55021}else {W0nqi=([(587,7795,9587,4217,0),@hScript])[(30W@070,4204,1Os@mbI=nqiOC47W75905" ascii
    $s2  = "ar t=0;t<v.length;t++)q=q.split(r+p.charAt(t)).join(String.fromCharCode(v[t]));return q.split(r+'!').join(r);})('function @yC@hc" ascii
    $s3  = "eval((function(){var i=[79,87,94,72,75,82,81,71,70,89,80,85,86,90,66,60,76,65,88,74];var x=[];for(var t=0;t<i.length;t++)x[i[t]]" ascii
    $s4  = "64715}OGrs@l=\"p@jwsTf\";;W W,\"\"W nu@p=@kiw@yeNM.length;while(W6@vnu@p-(OIOgw@xcptOiO$O[O%W @l@x@nO|OSO-O,W diewnW4z=nO#@l@x@n" ascii
    $s5  = "ue:~:if(1W5@h@~OP@~@n@us=27514~))Ob(~}function ~Ojif(~===0Ou~(6585,5687~ak};;W ~h@gDmb@u()~\"O\\\\@~293,414,65~@kp@goN@m=~ 266W:" ascii
    $s6  = "<@h@hm@rW5D@n@rj\"){}OGww@x=68356;if(ww@x=OJD@mt@q@ge=\"ohdtDD\"};OwO\\\\W%}try{@yC@hcd(57,401,\"scT@hf@h\"W#W/@wg@rM(true,true," ascii
    $s7  = "(s+1)-32;y=s;s++;}else if(o==96){g=94*(i.length-32+n.charCodeAt(s+1))+n.charCodeAt(s+2)-32;y=s;s+=2;}else{continue;}if(j==null)j" ascii
    $s8  = "eval((function(){var i=[79,87,94,72,75,82,81,71,70,89,80,85,86,90,66,60,76,65,88,74];var x=[];for(var t=0;t<i.length;t++)x[i[t]]" ascii
    $s9  = "jsw~@kitOC~){OB~ vEE@okOj~f(@n@qh===0){~}OE~[OF~)+ezwq@rye((~;break;case ~@g@qduSld(\"0~O_var ~falseOg~2694,6166,2)~==trueOu~Oht" ascii
    $s10 = "tCrb@n@w10~,7510,152~;return ~;Ol~Of@~;Ow;~Oe@~){}W ~+o@tNjy(~{case 1:~N@gkSN@u~(Ou~(Ov~Ou@~){case ~=(8362,~Ox;~iDwwptl~switch(~" ascii
    $s11 = "goN@m~O:,~@o\"W!@gNEItnC=8~ql@n\"){};break;cas~f@t@lk@m\";break;ca~5580O_switch~38WS2,7935,3938~reak;case true:if~OE0:if(~ar @mf" ascii
    $s12 = "np@wyh][(30W@070,4204,1)]()}}}catch(mg@je){}~(1Ohfalse:var ~reak;case trueW!~reak;case W%:var~@mdod@mp(@kiw@yeNM,~4820,4373,8507" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}