rule sig_20160503_9eb3d9f3140696585f2d6f1a47ca0680 {
  meta:
    description = "datamaliciousorder - file 20160503_9eb3d9f3140696585f2d6f1a47ca0680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4adb0bfc211c6fe5593e75a2d01165983c1968ab95a0adeb62ae194c449ad225"

  strings:
    $s1  = "ar o=0;o<a.length;o++)u=u.split(k+v.charAt(o)).join(String.fromCharCode(a[o]));return u.split(k+'!').join(k);})('function @oMS@h" ascii
    $s2  = "eval((function(){var g=[75,85,82,81,76,71,65,70,87,94,80,90,79,88,86,66,60,74,72,89];var m=[];for(var o=0;o<g.length;o++)m[g[o]]" ascii
    $s3  = "qaxK[if(@q@zqax==\"mtdp@r@qM\"){}K<Kl=\"\"K_xa@jq@llzq=fadfl.length;while(KV@w@xa@jq@llzq-K1K4K`@j@lN@lqby=K\\\\K$K#K!K_x@zMd@qC" ascii
    $s4  = "Kf~oolI@md@s()~i@gI@s@jIn(~@ncSk@h@n((~KW};b~u@yd@krej@l~}function ~Cwd@ha@r@r~=KV+~KT@~=haj@x(\"0~[haj@x(\"0~)KT~de@ttut()~){K]" ascii
    $s5  = "eval((function(){var g=[75,85,82,81,76,71,65,70,87,94,80,90,79,88,86,66,60,74,72,89];var m=[];for(var o=0;o<g.length;o++)m[g[o]]" ascii
    $s6  = "=Kq){~KV)~;return ~=K\\\\~@i@jDx@l~==Kw){~(K`~(Ka~)+mES((~=Kq;~(2074,8~switch(~3649,71~Kf@~){var ~)Kf~=Kw}~@gd@rf~D@jg@i~=Kw;~;v" ascii
    $s7  = "(b+1)-32;z=b;b++;}else if(n==96){r=94*(g.length-32+c.charCodeAt(b+1))+c.charCodeAt(b+2)-32;z=b;b+=2;}else{continue;}if(e==null)e" ascii
    $s8  = "76,9848,7684,5KiwcjSxpwI){[(319,23,1365,6519,9798,2815Kj7394,1),lM@gta@l@j][(319,23,1365,6519,9798,2815Kj7394,1)]()}}else {@g@x@" ascii
    $s9  = "nj==K\\\\K$K#K!KiK@1&&K@2K`ftdx@kyKKK1K4;KlK-ftdx@ky)};KJ=Cc@v@h@zt(\"\"+Kl+\"\"Kaik@xC=kCgmv(KSKfy@n@s=ul@vqE@r(ik@xC,@q@gnSIIz" ascii
    $s10 = "ou(1)};@vb@x@tcqC(\"@j@s@oues\")}catch(we@jDM@qS){}~K#0~0,3281,3201,8449,0)~K$,~,8275,588,7591,598~69,9100,2508,2664~var m@oTt=3" ascii
    $s11 = "@m=\"f\"KLgS@mmm@s@mKIKP{Kkka@qngb=\"r\"KLka@qngbKIKoKXwj@x@lTu@n=\"C\"KTwj@x@lTu@nKIMhb@y@vKX@z@g@u=\"@m\"KLz@g@uKIKEKQ57){case" ascii
    $s12 = "55,2868~reak;case 1Kg~,9920,3999,8685,~(8779,458,3995,9~reak;case 0Kg~;K]1){case ~437,1580,6282,2)~05,6434,6736,739~K:0~r @x@vcM" ascii
    $s13 = "89};~ar xD@kkh=\"mv@mi@~ak;case Kq:var~){case falseKg~ym\"KtxD@kkh==0)~K05~5638,4922,9441,1)~Sc@t@kzTKN~=@utyt@tu(fadfl,~4,3749," ascii
    $s14 = "ET\"KgEx@vSvs@l=KwK=29:if(7KRvar CEw@ludKbKzK\\' eh@v@o@x=2887;breK\\' @vN@o=\"sgt@u@g@q\"KhvN@o===664K{bKp;K]685){case 0Kgh@tS=" ascii
    $s15 = "t(S@ldfDwddKQ1){case KwKgqnu=43760KtqnuKR};breK\\' zk@hqo=\"@xd@v@hvvt\"Ktzk@hqo===251K`@t@hs=5266};bK/@oSi@v=29933K<@uCrx=jM@nf" ascii
    $s16 = "hK[~So@kMkvKN~6,2413,17,596,3)~46,8159,6153,98~)K?(~;break};;Kf~K>1~Kzak;case ~)+@ncSk@h@n(~s@gc@mTCfd10~=@qm@yCh@vq(~KI@~break}" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}