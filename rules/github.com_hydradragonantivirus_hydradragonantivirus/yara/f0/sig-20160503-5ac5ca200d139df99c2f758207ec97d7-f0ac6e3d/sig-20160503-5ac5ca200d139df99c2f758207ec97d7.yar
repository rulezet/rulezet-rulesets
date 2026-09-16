rule sig_20160503_5ac5ca200d139df99c2f758207ec97d7 {
  meta:
    description = "datamaliciousorder - file 20160503_5ac5ca200d139df99c2f758207ec97d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4f0521b6c19a1c9618fa926313d2b73ffc6727cad64b64c5fba7985a69b5f15"

  strings:
    $s1  = "q@w=XI};break}}try{vXfx@pia(1,Xc);ap@tE(1)XbN@xp@m(1,X[,X[)==0XR@pa@m=84949}XWdoq@pey@v=([(7686,7710,0),@nScript])[(5425,8508,88" ascii
    $s2  = "ar x=0;x<t.length;x++)c=c.split(v+e.charAt(x)).join(String.fromCharCode(t[x]));return c.split(v+'!').join(v);})('function N@xp@m" ascii
    $s3  = "eval((function(){var d=[88,80,66,71,60,70,82,87,86,79,89,75,72,65,94,76,90,85,74,81];var h=[];for(var x=0;x<d.length;x++)h[d[x]]" ascii
    $s4  = "ey=XcX2de@lx@oXZ f@xeos=6353;break}Xb5==1){}XWts@yE=42874;;XFflbN@oyNnX>Tq@v@x(XRu@rmtMx@qeXN00037Xi50091089101036001048002Xd190" ascii
    $s5  = "vXfx@pia(gkIr@h,kth){switch(gkIr@hXJ77XX@wMu=\"ob@tv@omi\"X6X[XX@lw@nbjd@n=12313;bX @mEyl@tM=23337X6X[XXcu@z@q@w=\"@xbw@q@g\"Xbc" ascii
    $s6  = "}X6455XX@v@n@vvXQif(@v@n@vv==423XR@jsp=69238XBbX @g@q@zp@zg=72404;break}X>Myrr@sc(XRf@xe@wn=[(4859,9888,4883,7126,5904,7285,1),@" ascii
    $s7  = "~){X]true:if(~X1r~r @i@r@ltg@g=\"@~=i@nNj@x(@lrm,~hS@zz\"){};brea~ak;X]525:va~X6\"~))+@pqfy@il((~X9v~vM@hS@zz\"){};~;break;X]~6)" ascii
    $s8  = "@hsE@gE(c@oE@t@lda@r)Xbztdf@hiIXG59037Xg54020005\")]==(9348,2154,2287,6473,8054,9567,1209,54Xl839,3518,200)){switch(3){X]78XXo@o" ascii
    $s9  = "eval((function(){var d=[88,80,66,71,60,70,82,87,86,79,89,75,72,65,94,76,90,85,74,81];var h=[];for(var x=0;x<d.length;x++)h[d[x]]" ascii
    $s10 = "i@tDp){switch(4){X]X[XX@p@one@s@hkXSX61:if(2==0XRvsI=XcXBswitch(1XJXX@ovn@mI=30631X6241:if(4=XIvar @vmc@vIvuXS}X6735XX@y@y@vf@nC" ascii
    $s11 = "==1XR@xdzepsg=10665}Xb1===254XRzdhk@hI=79492}XW@jh@oMu@rw=\"\"XW@m@zg@vii=@lrm.length;while(X^@k@m@zg@vii-(4555,56Xl6,Xq,8363,2)" ascii
    $s12 = "~X<(~(oEMtC===\"Nw~X>@~pDNNXTb~tC=31544;if~pk@g@q@x@ww~}function ~r@v\"XYj~jN@v@t==20~TT@rno\"){}~};break};~\"XF~XMs~sd@ler@v\"~" ascii
    $s13 = "Moc=70979XHXc){X]XcXXf@jS@mm@lr=27313Xbf@jS@mm@lr==XSXRw@z@v@nXS}X#Ilo=67348;break};;XWe@iy@qtxe@l=\"oXCe@iy@qtxe@lX>zw@y(XRTv@y" ascii
    $s14 = "f@ga[z@twCy](egn@p@rkgt)XWnSm@w=(6251,9805Xo5Xe8,2245,3);X^=XVnSm@w}XFIycI@qX>ap@tE(){switch(1XJXXwSv=83805XbwSv=XSXR@orrS=\"Tr@" ascii
    $s15 = "(u+1)-32;p=u;u++;}else if(y==96){m=94*(d.length-32+q.charCodeAt(u+1))+q.charCodeAt(u+2)-32;p=u;u+=2;}else{continue;}if(n==null)n" ascii
    $s16 = "~X%8~8,2302,9085,5372,0)~X61:var ~X&3~3437,1559,7644,263~72,132,9954,5055,~X*v~var i@nsErXQ~X.r~rph@v@n\";break};~))+zzwa@v@x@q(" ascii
    $s17 = "rn ~[i@rC(\"0~;switch(~==Xc){~){X]1~(1196,77~var @jN@~@v@t=\"h@~=i@rC(\"0~()XW~\"DSs@x\"~XS;~){var ~=X[~=Xc;~4==\"@q~X^+~;var ~:" ascii
    $s18 = "01,5)XYzMnT@in@rz){[(5425,8508,8811,2608,7581,122Xh,o@wblE][(5425,8508,8811,2608,7581,122Xh]()}}catch(@quv@t){}~reak;case trueXX" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}