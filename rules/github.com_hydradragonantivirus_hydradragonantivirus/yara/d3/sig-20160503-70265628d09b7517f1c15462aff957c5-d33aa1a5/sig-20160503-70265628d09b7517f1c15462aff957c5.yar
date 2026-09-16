rule sig_20160503_70265628d09b7517f1c15462aff957c5 {
  meta:
    description = "datamaliciousorder - file 20160503_70265628d09b7517f1c15462aff957c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fca0a52aed8a397aee668cdb71c2955d9c2387c879396e32c0aefb9c7073f60"

  strings:
    $s1  = "eval((function(){var p=[85,74,80,86,65,66,81,60,88,94,82,76,90,71,70,72,87,75,79,89];var u=[];for(var e=0;e<p.length;e++)u[p[e]]" ascii
    $s2  = "\"@g@y@gtvg\",0,true)}J&i@zhdj@wh(0)U\\\\f@lf=([(1010,4680,3487,5948,6457,4184,438,8612,0),@wScript])[(1230Ut2892,2253,7708,6733" ascii
    $s3  = "ar e=0;e<d.length;e++)w=w.split(y+g.charAt(e)).join(String.fromCharCode(d[e]));return w.split(y+'!').join(y);})('function lykzC(" ascii
    $s4  = "A22050055058J+fw@s@t@rN@o,nq@v@l@lp@l,false)U/\"@ySU}U^U,\"eU_ UVUWUKUBoUJU#nmUMU>UeUPrmUOU9U= UNU;U<3;U[UA10J/60048J+UjpM@g@tuw" ascii
    $s5  = "f(@ijT@uIE~UWi~@izMIm=2931~@rs@ix@u@vq~S=76817;bre~Up@y@s@~}function ~i@jheS@ywe~;J\";;;~@g@sd@lmnt~vNlUp@~@ijT@uIE=\"~mzTNp@yw" ascii
    $s6  = "eval((function(){var p=[85,74,80,86,65,66,81,60,88,94,82,76,90,71,70,72,87,75,79,89];var u=[];for(var e=0;e<p.length;e++)u[p[e]]" ascii
    $s7  = "5060J+@tI@w@oduw@r,(9859,462,254,2223,1629,1847,0))};@m@j@rbg@s(@x@od,Nr@jC)UQi@zhdj@wh(@xCNr@z){switch(\"ECx\"Ug0:J\\'@mtpz=\"a" ascii
    $s8  = "(k+1)-32;j=k;k++;}else if(q==96){r=94*(p.length-32+t.charCodeAt(k+1))+t.charCodeAt(k+2)-32;j=k;k+=2;}else{continue;}if(m==null)m" ascii
    $s9  = "@w@yE@tUo;UIf@zD=52436J&f@zD===236Uk@mgabvUoJ#UT=\"Um@tz@qh=m@u@l@s.length;while(UR@n@tz@qh-(488U6U5Ukf@qwu@jMgsU8J#oo@ytgC=UF(U" ascii
    $s10 = "93,1671,249~U66~64,6330,6907,2)~8,3946,9565,87~case true:J\\'~=(6030,7374,0)~ak}UzgstiE~rmUOa~=49087J&@rs@~ix@u@vq==1){};~=\"@vq" ascii
    $s11 = "\"Ua~)Ua~@tnI@ma@u~e@ykerdCu~==1Uk~ySU}a~ar @veou=~vvNl\":var~J%ch(~;return ~(Uj@~){}J#~@ltn@hDo~S@w@g@or~(Uk~){case ~ @gf@sk~;b" ascii
    $s12 = "78;J\";~7600,4196,4043,1)~U17~falseUicase ~;@rnTdrvx[Tw@t@v@~break;case 0:J\\'~U`6){case ~U34~4,701,3913,9985,~J\\'@j@y@jb=tru~1" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}