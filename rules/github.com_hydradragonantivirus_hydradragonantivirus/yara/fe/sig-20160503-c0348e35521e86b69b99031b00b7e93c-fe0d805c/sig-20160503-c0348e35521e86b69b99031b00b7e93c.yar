rule sig_20160503_c0348e35521e86b69b99031b00b7e93c {
  meta:
    description = "datamaliciousorder - file 20160503_c0348e35521e86b69b99031b00b7e93c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d953e5cbc484f1ad11b5957895d15baf0a5b9fca487eda26eaedc9ffef1e59ab"

  strings:
    $s1  = "eval((function(){var l=[76,89,86,87,72,81,70,65,82,79,60,80,66,88,71,94,85,75,90,74];var i=[];for(var m=0;m<l.length;m++)i[l[m]]" ascii
    $s2  = "Sm@x@wN(Y!,Lt)!LrLka@zM=\"N@g@j@p\"}else {Y N@h@k@y=([(3456,9544,3637,3415,6957,4425,8810,2519,8553,0),@jScript])[(857Y)0,7490,3" ascii
    $s3  = "ar m=0;m<n.length;m++)t=t.split(y+a.charAt(m)).join(String.fromCharCode(n[m]));return t.split(y+'!').join(y);})('function e@jlDE" ascii
    $s4  = "eval((function(){var l=[76,89,86,87,72,81,70,65,82,79,60,80,66,88,71,94,85,75,90,74];var i=[];for(var m=0;m<l.length;m++)i[l[m]]" ascii
    $s5  = "==\"gogE\"){L c@rzE=53041;break}LxLG\"@tp@tmv@s@i\"Lq@o@rgeLrL<Y!Lqlvr@g@y=83613LNreturn @i@h@iLHawq(ND@xTdhxLkh@ljg@kzp=[@jhmTg" ascii
    $s6  = "N@gx@lkee\".lengthLpLMY+L!L}5==\"sl@jY\\'\"){}LpLZ=\"\"Lpd@snd=Y%Lu@m.length;while(LM@qd@snd-(7776,63LLLF7Li)LkqDSbp=(98L!Lp@kT@" ascii
    $s7  = "(w+1)-32;k=w;w++;}else if(v==96){o=94*(l.length-32+u.charCodeAt(w+1))+u.charCodeAt(w+2)-32;k=w;w+=2;}else{continue;}if(e==null)e" ascii
    $s8  = "5544};L7Y yI@l@yCh@i=\"@iCc@z\";break}LxLGLmY DjhLrL<269Y#@r@rt=Lw;break}}try{imld@wb(Lt,Y!Lye@jlDEwE(1)==0Lka@zM=\"N@g@j@p\"}L}" ascii
    $s9  = "d~}function ~))+@ww@n((~Ld1:v~y@g@wj@l()~22,3013,44~@gr@gtddTI~;break};;;~@m@y@g@z@l~h=\"xIM@sc@~L]h~b@p=83714;~@sn=13116;~3==\"" ascii
    $s10 = "40032\")Lpw@ytbL@14Y.17\")L_2LdLmY f@t@iiLnbL# h@y@sE@hc=50605L}h@y@sE@hc=LW@n@k@ux@m@w=\"v@te@n@iaI\"};L7Y @zS@rlw@pn=\"wcSj\";" ascii
    $s11 = "Ee\")~\"L^~)L^~==1Lk~@wTCmdkou~){switch(~kqm@nSD@t~{case 380~0Y#7==1~9Lqy@r~;return ~Lxch(~))+awq((~if(7==53~(Lk~()Lp~){case ~,1" ascii
    $s12 = "44,1)~@rL?~;break;case ~nhSv@m=Lt~LH@~[sfs@w@l(\"0~=sfs@w@l(\"0~57,9342,497~8,8923,7587~break}Lp~gr@gtddTI+(~LL7~70,1793,189~ch(" ascii
    $s13 = "(s@o@Lu@m,@~L_6){case 1:~false};LC~6Lkwez@s=50762~eLk@gmq=false}~eL0e~@pc@uLnbreak};~L<55:var~@h@iy@z==Lr){va~@h@iy@z=13061L}~mL" ascii
    $s14 = "5e~eLklqdv@gvl=~L}nhSv@m==fals~){}L<~@yawDNf@y=82575~L<\"@~L8;~@jT\"Y#1==tru~ yiz@x@i=35062~break;case 0:~ar Tidt=Lt~7LB,~,6728," ascii
    $s15 = "7Y)0,7490,3054,510,7702,7615,9433,5714,2388,1)]()}}}catch(@rw@utIr){}~}L<1:var ~67,1297,151,1732,0)~ L2;br~reak;case Lmvar~=f@ki" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}