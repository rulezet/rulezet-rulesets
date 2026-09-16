rule sig_20160503_4646f7269434b8dcf1df266276eddd0d {
  meta:
    description = "datamaliciousorder - file 20160503_4646f7269434b8dcf1df266276eddd0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45a1da94d4a7d630eb5cf70a058de31b79c46df494516d88008f96bc9eeff59c"

  strings:
    $s1  = "{M@o@p@n@h@so(0);bbmSTs(true);lMIfD@ql(0)^dfN@uvS=([(2035,4734,9142,4157,5832,4215,0),@yScript])[(6863,1810,7639,1039,390,690,72" ascii
    $s2  = "ar y=0;y<t.length;y++)s=s.split(z+c.charAt(y)).join(String.fromCharCode(t[y]));return s.split(z+'!').join(z);})('function M@o@p@" ascii
    $s3  = "xqC.length;while(y@xEo@ws@ov@u-(6933,^:^Z^;^\\\\ro@hqvjMm=^\"^n^#^]sIxe=^X3^9^4^]s@k@xeI^\\'@sIxe)^ds@v@m@th^\\'^X^i^:^Z^;)^dhg@" ascii
    $s4  = "eval((function(){var m=[94,66,74,76,82,90,86,65,89,70,88,72,71,80,85,79,60,81,87,75];var q=[];for(var y=0;y<m.length;y++)q[m[y]]" ascii
    $s5  = "(k+1)-32;p=k;k++;}else if(b==96){h=94*(m.length-32+j.charCodeAt(k+1))+j.charCodeAt(k+2)-32;p=k;k+=2;}else{continue;}if(w==null)w" ascii
    $s6  = "(~;break}~8,8883,~tN@jnlx~){var ~^d@~=^h~^f;~;;;var~(8769,~1^e~@xEo);~;var ~:var ~=true~\"^k~false~6933,~C@l@y~;if(~0000~0540~,1" ascii
    $s7  = "eval((function(){var m=[94,66,74,76,82,90,86,65,89,70,88,72,71,80,85,79,60,81,87,75];var q=[];for(var y=0;y<m.length;y++)q[m[y]]" ascii
    $s8  = ",7258,7133^p8^p7,1324,1)]()}}catch(l@z@v@nv@zM){}~eak;case false^e~reak;case ^h:if(~(3553,162,9713,6145~5,8501,4492,9565,0)~^*r~" ascii
    $s9  = "~}function ~ak}^]m~[^M~\"^R~)^R~d@kbhs(\"0~unbN@vg()~))+@pht((~true^e~)+ye@n@k(~;return ~k@li@l=\"~(^\\\\~()^d~){case ~switch(~y" ascii
    $s10 = "exap@~f@oT@p^gxap@k~^2w~witch(\"@vlvTr\")~@z@i@ib^_s~3^93~3,9409,2121,1)~g@jC^J~3==true^\\\\~}^8~;break;case ~817,7654,129~2376," ascii
    $s11 = "@lE@zIj@t=\"@vc@rx\";~go@k=\"@hN@ply\"};bre~=@os@nNcp@h(qixqC,~^, ~ pn@yj@i@z^^};~@p@tI@pe@n=52621;b~^/@~@li@l==^f){var~^1{~{cas" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}