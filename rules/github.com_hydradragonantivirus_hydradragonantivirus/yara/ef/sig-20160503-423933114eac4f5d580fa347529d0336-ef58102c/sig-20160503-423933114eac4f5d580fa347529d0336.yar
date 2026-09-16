rule sig_20160503_423933114eac4f5d580fa347529d0336 {
  meta:
    description = "datamaliciousorder - file 20160503_423933114eac4f5d580fa347529d0336.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac7bd78441d0a2133ea0eed2b1d4450d1bd3b20b499087ea28f9d8ba32d507d6"

  strings:
    $s1  = "ar p=0;p<h.length;p++)s=s.split(z+g.charAt(p)).join(String.fromCharCode(h[p]));return s.split(z+'!').join(z);})('function by@p@g" ascii
    $s2  = "eval((function(){var y=[81,79,65,71,82,94,85,75,80,72,66,89,88,70,90,60,74,86,87,76];var n=[];for(var p=0;p<y.length;p++)n[y[p]]" ascii
    $s3  = "7711Q4if(3===1){Q<Qr @omogQqQ@QV@kc@umu=\"@g@oh@o@k\";break}Q\\\\6Qf1Qpu@m@z@piSr=\"Cjttls@j\"Qwu@m@z@piSr===0Qcomn@gg=82820}Q4i" ascii
    $s4  = "eval((function(){var y=[81,79,65,71,82,94,85,75,80,72,66,89,88,70,90,60,74,86,87,76];var n=[];for(var p=0;p<y.length;p++)n[y[p]]" ascii
    $s5  = "){QQif(6===1Qcs@x@ocD@ruQl}QoQi\"\"QosCNicu=@rhlMqD@p@j.length;while(Qj@vsCNicu-(Q6Q3Q/Q,QctDv@g@u@wv=O\"Q&Q%Q\"Qkh@zE=QTQ-Q(Q+Q" ascii
    $s6  = "80,2199,6754,741,2885,253O%0,1),TiS][(4696,6880,2199,6754,741,2885,253O%0,1)]()}}else {j@jv@g@m@s(138,O )}Qwby@p@gg(\"S@zmz\",O " ascii
    $s7  = "Nh===\"@sTfeM\"Qck@gh@xgE@h=\"N@z@iy@x\"QQQx@g@r@gM@s@hQqQ\\\\6Qf1QpdikD@p=9884;break;Q1fheIQ#148Qy2==280Qmwa@jQlQ<407Qy3==Ql){}" ascii
    $s8  = "19O$26022\")]=hD@grNoq@tQowoy@s=\"lz@r@w\"Q\\\\2QfQr ft@zsCN=52957;break;Q1n@gvCn@w=1711Q@743Qp@z@x@j@ngkQlQ_;O#Q*43O,6105105103" ascii
    $s9  = "(k+1)-32;x=k;k++;}else if(e==96){i=94*(y.length-32+d.charCodeAt(k+1))+d.charCodeAt(k+2)-32;x=k;k+=2;}else{continue;}if(t==null)t" ascii
    $s10 = "uobQlQ\\\\2QfQV@s@rSzCf=12175;break;Q1T@xaI=38855Q@\"D@mcd\"Qpd@sd=\"@p@r@ix@j\"Q4Qx@m@qMNxQqQtm@qMNx=QqQmDchQq}Q5fajhgvgu=@q@xs" ascii
    $s11 = "@rp~@j@rb@uSahq~mb@u=\"@kE@i~xSQR~}function ~\"@n@zu\":va~Q]@~=@hCfy(\"0~}Q_~[@hCfy(\"0~))+CO((~Qj+(~\"Q]~trueQp~)Q]~@kgd@pr()~Q" ascii
    $s12 = "Qj);~rIbb@n@jl~;switch(~;return ~(Qc~;break};~Qkg@~@xxE@k()~@k@hjyf(~Qm@~()Qo~(Qm~){case ~i@g@i@p~@rzv@w(~@s@nwo=~@k@t@qN~Qo@~=Q" ascii
    $s13 = "@h@mfdekiu\")Q=s@hie@z@g@w=56358}}catch(@ibdjfsk){}~jxbu@j(@rhlMqD@p@j,~Q%5~5,3121,3092,7345,0)~=falseQ@~Q&1~1151,7828,1119,747~" ascii
    $s14 = "=43279Qwq@~}Q@~=Ql){var ~QC\"~\"@pSo@r@jbiI\"~;break;case ~=falseQk~QK@~@mb\"Q\\\\~QM@~))+Qh(~itch(O ){~2,4705,22,3~(1588,6931,~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}