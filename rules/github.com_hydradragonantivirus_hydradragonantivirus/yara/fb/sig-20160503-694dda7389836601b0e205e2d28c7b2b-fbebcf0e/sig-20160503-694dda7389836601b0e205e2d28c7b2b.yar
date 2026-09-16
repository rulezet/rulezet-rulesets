rule sig_20160503_694dda7389836601b0e205e2d28c7b2b {
  meta:
    description = "datamaliciousorder - file 20160503_694dda7389836601b0e205e2d28c7b2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3f99c6f74a36e93e6a624deda747a674035381a5ffd824aa7a07e9361ed7288"

  strings:
    $s1  = "eval((function(){var w=[60,72,74,75,88,90,86,89,94,65,85,71,66,87,70,79,82,81,80,76];var d=[];for(var i=0;i<w.length;i++)d[w[i]]" ascii
    $s2  = "ar i=0;i<x.length;i++)v=v.split(f+u.charAt(i)).join(String.fromCharCode(x[i]));return v.split(f+'!').join(f);})('function @t@sg@" ascii
    $s3  = "a~hI@v@wDsnx10~<B@~@w@urj@v(\"0~@sxS@h@pruv~C@i@uhEgM()~o@n@yrjnd((~){};bre<r~}function ~))+<V~==1<W@~=<`;if(~<H@~};<Q~;return ~" ascii
    $s4  = "p@i=<`<91<p2==336<W@tSl@ttx=\"M@t@vvkT\"};break<G1<N0<p3==\"s@vEC\"<Wd@slMy=\"@nuxv\"<5259<p1==1<WM@y@w@k@h<b};break}<Pnd@n@t@wM" ascii
    $s5  = "gth<^<l<6<!;<Q6<N635<_Ic@rze=29420<9\"o@jDafxTp\"<_@zel@r@u=\"g@ywhs<a@zel@r@u=<R<A;<^<Y=\"\"<^b@rnzz@m@l=l<s@l@s.length;while(<" ascii
    $s6  = "eval((function(){var w=[60,72,74,75,88,90,86,89,94,65,85,71,66,87,70,79,82,81,80,76];var d=[];for(var i=0;i<w.length;i++)d[w[i]]" ascii
    $s7  = "bre~eak;case true<_~<)e~<* ~ C@rj@ske=<`;b~nb@w@soqz=7369;br~ch(1<N1:var~465,4784,7609,1)~@nId<8~8189,7461,8393,3~000,5610,6004," ascii
    $s8  = "(a+1)-32;q=a;a++;}else if(s==96){h=94*(w.length-32+j.charCodeAt(a+1))+j.charCodeAt(a+2)-32;q=a;a+=2;}else{continue;}if(k==null)k" ascii
    $s9  = "O@~){}<^~c@m@m@pf~(<X~<X@~){case ~(<W~;;<^~switch(~==<`~\";break~=<l+(~=ukxow(~@xdky((~){var ~)<^~E@lb@z~,1060,~M@rq@u~){swit~)]" ascii
    $s10 = "1107,4838,4545,1068,546<Z1)]()}}catch(@sy@k@h@ku){}~eak;case false<_~74,1666,2738,829,0)~=@ic@wvt(l<s@l@s,~ @<)~c@q@hy=\"C@p@lf" ascii
    $s11 = "2)~,4354,1980,6223,~T@zh<8~b@t=\"lM@q@w@zt\";~,8118,9846,4321~<43~))+<@~}<9~=(61<o25,59~@p@n@p@wDtC@z~[<=~;break;case ~@u@l@wp@j" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}