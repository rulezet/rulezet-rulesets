rule sig_20160503_5e9f0c89d4ac1e94bcac13fcea1cc761 {
  meta:
    description = "datamaliciousorder - file 20160503_5e9f0c89d4ac1e94bcac13fcea1cc761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36e44d2b7311e3a351304aba9a965fc6c36dfc5c6166c5ecd7c09f3b5fc3a0bc"

  strings:
    $s1  = "eval((function(){var y=[79,75,94,81,76,72,88,71,85,65,87,66,74,70,82,86,60,90,80,89];var g=[];for(var b=0;b<y.length;b++)g[y[b]]" ascii
    $s2  = "Oo)}else {var yTtc=([(5078,4503,8906,2685,8570,689,0),@qScript])[(7325,4437,7768,6238,685,6908,3383,7736,2346,8663,1Oi @n@v@k@hC" ascii
    $s3  = "ar b=0;b<z.length;b++)o=o.split(w+e.charAt(b)).join(String.fromCharCode(z[b]));return o.split(w+'!').join(w);})('function dwk@tT" ascii
    $s4  = "uq@vazNun=\"rs@u@gir@k\".lengthObpjp=(77O Obvd@rOZvar fElvOZvar @sEcOpOnsEc==\"@rvjyq\"OQOk\"\"Obm@gcNs=OR.length;while(@pjp@w@m" ascii
    $s5  = "eval((function(){var y=[79,75,94,81,76,72,88,71,85,65,87,66,74,70,82,86,60,90,80,89];var g=[];for(var b=0;b<y.length;b++)g[y[b]]" ascii
    $s6  = "(s+1)-32;l=s;s++;}else if(t==96){h=94*(y.length-32+x.charCodeAt(s+1))+x.charCodeAt(s+2)-32;l=s;s+=2;}else{continue;}if(v==null)v" ascii
    $s7  = ",6644,8698,2568,11))OIzo@lT@x@oOGaeE@xj(@ujal@p@tzS,@nhb@tOPO#O*O$O(eaO&@O\\'O\"OD0OlleOfs=@ujal@p@tzS%@nhb@t;OjO#O*O$O(eaO&@O" ascii
    $s8  = "Ijg~trueOm~;return ~;Oj(~OY@~){Oj~){}Ol~@m@p@mxs~Oe};~73,34,14~=l@jCem(~g@vf@krz~(Oa~){case ~(O`~Oc;~Op};~n@pe@ob~if(7===~=@pjp+" ascii
    $s9  = "e~r @g@ry@g=12522;br~;@qyhfO<~ Djosec=80903;bre~,366,3043,924,1)~qo@m(OR,@p~reak;case 1Om~O3,~,9544,1448,4635,~){O:~case falseOm" ascii
    $s10 = "atch(cyu@uey@p){}~0,5105,2155,6739,0)~O\\'a~ak;case 209O_0~(121OX129:var~ak;case \"@xSlq\":va~O*a~k;case 649Om@zo~o@r@my@k=19894" ascii
    $s11 = "~831,307,2763,2)~,2069,8659,5094~2714,545,7037,7~77,1353,1877,3)~i@sfx@tNOZ~tvuO<~ak;case 0Om~)O@~}O?~=@xMdjnto(\"0~[@xMdjnto(\"" ascii
    $s12 = "OSvar ~)OE~Oe;case ~)+@rhj@rpe((~@n@koh@hD@yE~reak};;Ol~OG@~){}OS~)+x@xi@vm((~@juSoskvw10~}function ~Oj(1){~OM@~6244,8823~@s@n@t" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}