rule sig_20160503_24613f02f67d230b0b13f44eb3072765 {
  meta:
    description = "datamaliciousorder - file 20160503_24613f02f67d230b0b13f44eb3072765.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a82a1837775d1148c6db4c826c723aa1642621e4bb8c051831fd14663d254a3"

  strings:
    $s1  = "}else {if(@seM@og(true,279)!=1Br z@iv=43082}else {BykId=([(6571,8136,0),@rScript])[(2622,2178,307,3638,4148,7024,4276,2949,1Bm@z" ascii
    $s2  = "ar v=0;v<k.length;v++)l=l.split(c+m.charAt(v)).join(String.fromCharCode(k[v]));return l.split(c+'!').join(c);})('function zIoynS" ascii
    $s3  = "eval((function(){var o=[66,76,70,89,75,94,65,86,80,72,90,87,85,60,79,71,74,88,81,82];var a=[];for(var v=0;v<o.length;v++)a[o[v]]" ascii
    $s4  = "(i+1)-32;e=i;i++;}else if(z==96){x=94*(o.length-32+p.charCodeAt(i+1))+p.charCodeAt(i+2)-32;e=i;i+=2;}else{continue;}if(u==null)u" ascii
    $s5  = "hml@y@z@j\"BpdCkn@v@jiS=nqT@ogzg.lengthBpB^=(B#B!Bp@r@sj=\"yMfeq\"Bvr@sj===1){}Bp@jBb=\"\"BpNum@sT=@qvE.length;while(B^@tNum@sT-" ascii
    $s6  = "eval((function(){var o=[66,76,70,89,75,94,65,86,80,72,90,87,85,60,79,71,74,88,81,82];var a=[];for(var v=0;v<o.length;v++)a[o[v]]" ascii
    $s7  = "@jh@qn@u@j((~=mx@qTIo@z(@qvE,~B/v~vmN@g@yBiif~B2;~;case 1Bs@j@~[B8~B5\"~\"xammj\"};break~Ba0:var ~=true;B_~Br M@qp@x=~B<)~se \"N" ascii
    $s8  = "@uh@y){[(2622,2178,307,3638,4148,7024,4276,2949,1),@oy@ym@qEh][(2622,2178,307,3638,4148,7024,4276,2949,1)]()}}}}catch(w@urIy){}~" ascii
    $s9  = "~r Bj@~@wC=23002;~@g@rb@whMp~\"BU~dlpi=\"@x@~;return ~B]@~ @mDy@o@~B^+~;bBq;~NT@hr@vo~(Br ~Br @~(Bn~EiTe@yk~switch(~Bn@~){case ~" ascii
    $s10 = "5306,~,1546,5653,1~0,3553,8762,~0BO,~,4314,9751,2~@m@u@s@oq@z(~BK@~break;case ~}function ~))+ro@pf((~Byi@pf@q~=Bt){};~,6359,1004" ascii
    $s11 = "sT@n=11325BvsT@n===\"ykEa@qNI@n\"){}BB0:if(7==1){}BB508Bsts@iemBtBYBy@sC@u@r=\"b@zt@p@q\";B_trueBa553Bsyeu=74321BxyeuB:break;cas" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}