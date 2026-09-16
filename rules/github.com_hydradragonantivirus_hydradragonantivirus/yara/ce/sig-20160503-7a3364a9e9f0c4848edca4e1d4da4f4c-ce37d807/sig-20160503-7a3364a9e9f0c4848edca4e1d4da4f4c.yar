rule sig_20160503_7a3364a9e9f0c4848edca4e1d4da4f4c {
  meta:
    description = "datamaliciousorder - file 20160503_7a3364a9e9f0c4848edca4e1d4da4f4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd4dbd9db538cafe5767de701246facc43cc92da1fac699acca261ac592ebebd"

  strings:
    $s1  = "ar m=0;m<b.length;m++)c=c.split(y+i.charAt(m)).join(String.fromCharCode(b[m]));return c.split(y+'!').join(y);})('function SMf@g(" ascii
    $s2  = "0WiN@k@p@k@zm=9746}W$env@rnDe=75720;break}WNR#W`1Wor@nbg=\"@l@hM@gv\"W6WF@k@ogk@ruN=\"mwuo@qa\"W$p@z@u=9605W|p@z@u==Wj){}W7@h@yb" ascii
    $s3  = "eval((function(){var j=[87,82,74,89,80,81,88,70,90,85,65,71,75,72,66,94,86,60,79,76];var q=[];for(var m=0;m<j.length;m++)q[j[m]]" ascii
    $s4  = "eval((function(){var j=[87,82,74,89,80,81,88,70,90,85,65,71,75,72,66,94,86,60,79,76];var q=[];for(var m=0;m<j.length;m++)q[j[m]]" ascii
    $s5  = "o@i,~W&7~7,9885,8099,3849,0)~W60:var ~W(,~,7903,7583,3376,70~ch(1W`false:~132,9726,692,4309~W.{~{WrotNCT=78518~bm@hMk@q\";break}" ascii
    $s6  = "(l+1)-32;x=l;l++;}else if(p==96){s=94*(j.length-32+u.charCodeAt(l+1))+u.charCodeAt(l+2)-32;x=l;l+=2;}else{continue;}if(f==null)f" ascii
    $s7  = "th;while(Wu@xz@z@u@ir-(959WCWBW@W=)Wi@t@pbfirf=(4W(W&W#WnnT@ouneWdW:)Wnkax@wnjq@z=@W!nT@oune)WnMkio@p=@W!Wu+(959WCWBW@W=))Wn@j@u" ascii
    $s8  = "dM=\"fWJ@w@thfrtdMWAIWV{R\"oj@o@lqvs=\"rWJoj@o@lqvsW>kSMsW_Md@mM@m=\"CWJMd@mM@mWAbvhW_@hyggqMI=\"@qWJ@hyggqMIWArDo@q(){switch(4W" ascii
    $s9  = "+@ijgf@r((~@gwq=64605;i~(6608,7307,1~@jv[WQ~W@,~,4282,8400,2~WA@~WB7~7,3692,7387~}function ~1,6241,345~5,9201,588~;break};;;~[WQ" ascii
    $s10 = "3~falseWo~IW\\\\m~mum@t@g@n\"~@rvWa~\"WM~@s@q@g=\"T~=WQ~;return ~;switch(~Wb@~ar @nz@s~q@s@n(\"0~TkMEm@qw~@sn@zvxn~=1Wi~){}Wn~gb" ascii
    $s11 = "\"Wq3WY}WN1W`R#WoEoImcp@nWjW$@zp@lbR+@l=74590WDWWWE4000R!11R @siyve,@m@krop,false)WNWlWX7W^W]W$R1W\\\\WHW7MWI3;WW[WQ62W}23001\")" ascii
    $s12 = "Wqjb@iI){[(1811R01,1562,4687,1652,7663,1),bmlIst][(1811R01,1562,4687,1652,7663,1)]()}}catch(Mb@yntM){}~}W61:var ~n@o@y@simd(k@o@" ascii
    $s13 = "~@hy@pN@m~\"W`~=Wp){~Wh8~8,5835,3~a@t@g=\"n~==532){}~86:if(1=~(Wi~){case ~Wj;~()Wn~,7403,5~=Wu+~91,6245~4Wv9~Wu);~376,712~){R\"~" ascii
    $s14 = "~W1@~@u@li=65832;swit~(5===\"ti@zD@nm\")~))+n@zR,y@o((~W32~21525}Wn@i@g~W5t~trueWisNz=~W9f~f(@nz@s@gwq==~;break;case ~;break}Wn~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}