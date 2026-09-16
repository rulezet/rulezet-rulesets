rule sig_20160503_3ee65eb099baee84f3fcb4fbab4fb5e4 {
  meta:
    description = "datamaliciousorder - file 20160503_3ee65eb099baee84f3fcb4fbab4fb5e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea042803124120ab8b4b5e977b46ee5654e1432594f7cfbf95313b8df2abd5b"

  strings:
    $s1  = "eval((function(){var p=[89,88,75,81,86,94,70,76,82,79,85,80,87,72,66,74,60,90,65,71];var e=[];for(var d=0;d<p.length;d++)e[p[d]]" ascii
    $s2  = "ar d=0;d<q.length;d++)j=j.split(i+r.charAt(d)).join(String.fromCharCode(q[d]));return j.split(i+'!').join(i);})('function Mhmp@n" ascii
    $s3  = "h;while(@YI@wevNMk@n@t-Y.{Ytj@gatY-YbvfrIoY8YAY&Y\"YWhjf@nT@tbY+vfrIoYUhuf@hYaY\\'+Y.YWu@nlMwYaY\\');Y==@u@nlMw+@hjf@nT@tb+huf@h" ascii
    $s4  = "][(13Y{423,1)]()}}catch(@onknC){}~ueYey@psp==1){};~Y&9~9,9604,1548,9467,1)~CdmI@hY2~1YP@y@psp=tr~=falseY7~,8451,6006,258,151~m@o" ascii
    $s5  = "\"YB~30Y{345~;return ~;switch(~Y]};~))+X!(~I@p@g@kd~=1YV~YWt@~hniqo@kw~{Ym==~M@gcrq@n~YS1~g@j@ji()~=Yd){~ksekN@pT~){}Yb~bd@pfe10" ascii
    $s6  = "(f+1)-32;w=f;f++;}else if(t==96){c=94*(p.length-32+k.charCodeAt(f+1))+k.charCodeAt(f+2)-32;w=f;f+=2;}else{continue;}if(l==null)l" ascii
    $s7  = "mg@j@hj@t+Y\\\\][llEk]YBcde@mvkY9p@gbx@jrg(En@u@o@xwj@m){switch(4YSY`if(3==YGuvjd@toNYdY41Yhd@y@vi=56446Y]}YCYxYL68:Ycs@x@jY%Y`Y" ascii
    $s8  = "eval((function(){var p=[89,88,75,81,86,94,70,76,82,79,85,80,87,72,66,74,60,90,65,71];var e=[];for(var d=0;d<p.length;d++)e[p[d]]" ascii
    $s9  = "(YV~){case ~YZ}~)Yb~){Yt~Yb@~0Yh~Yd;~=Yl~o@nfC(~T@xbxn~;break~);@y@p~)];var~Yl:~=x@s@i~;Yt~Yt@~=Yx~Yy@~00604~90320~:Yt~if(4=~5,1" ascii
    $s10 = "qsyh@o(\"0~==falseYV~}Y7~aum@p@j@i@n()~(5664,6868,3)~Y];case ~=@YI+(~Y;@~@kzqb@t@g()~}function ~))+Y[(~@i@uqwzt@p~(YA~=u@ol@vCb(" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}