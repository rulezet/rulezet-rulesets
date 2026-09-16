rule sig_20160503_ab2274dbc383e19ea1135eb7e1bb5080 {
  meta:
    description = "datamaliciousorder - file 20160503_ab2274dbc383e19ea1135eb7e1bb5080.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe81bcfa27c1a47d1298bd3a1dfa1247d7b806898260ea1ef4c838b0f622b2f"

  strings:
    $s1  = "eval((function(){var l=[82,79,90,85,70,72,75,71,94,60,87,81,74,65,89,86,66,80,76,88];var r=[];for(var c=0;c<l.length;c++)r[l[c]]" ascii
    $s2  = "ar c=0;c<y.length;c++)n=n.split(h+q.charAt(c)).join(String.fromCharCode(y[c]));return n.split(h+'!').join(h);})('function njSCM(" ascii
    $s3  = "Rishk=52619ReesDk@g@h=\"co@qiSe@i\"RevE@wj@r@qt=\"eDelo\"R_ iEg@u=\"oRIiEg@uRCb@gny@m@vRSe@miqj=\"cRIe@miqjRCR4{var yND@s@h=\"aR" ascii
    $s4  = "while(RY@p@kv@xoD@i@yr-R1R$,543R#RZpeTcR>R RvR!R[uw@qI@htmRJR=R\"102,4509,1R\\\\TmDR0@uw@qI@htmR\\\\C@umg=o@gR%+R1R$,543R#)R[g@w" ascii
    $s5  = "@n@iwa,Ctqo,biTe@k){RVCtqoRTRtR^u@n@j@z=11365R<truR^@iscph=RtR9RtR^@xm@tI@h@qmRcbreak}RO0}try{if(@tnT@n(1,true,true)Ro@l@mNt@m@g" ascii
    $s6  = "eval((function(){var l=[82,79,90,85,70,72,75,71,94,60,87,81,74,65,89,86,66,80,76,88];var r=[];for(var c=0;c<l.length;c++)r[l[c]]" ascii
    $s7  = "yby,Ra){RVRaRTRtR^oENckx=41612R<truR^uaf@yml@g=5526R<1:if(Ra=Roif(Ra=Ro}R[qMg@uRh};break}ROtrueRCb@u@i@q(k@wl@lRZImaRpr=parseInt" ascii
    $s8  = "(o+1)-32;f=o;o++;}else if(w==96){v=94*(l.length-32+m.charCodeAt(o+1))+m.charCodeAt(o+2)-32;f=o;o+=2;}else{continue;}if(j==null)j" ascii
    $s9  = "]){};~}function ~))RW(~(9678,7143~+ir@sia@w(~RP;;~RO@~\"RO~=RY+~d@j@heS()~@lp@k@q()~==1RZ~)RR~;return ~;break};~RU@~;RV~(RZ~){ca" ascii
    $s10 = "[(6132,6256,1203,1113,1),@hizhgy][(6132,6256,1203,1113,1)]()}}}catch(llbr@kdw){}~3798,5842,3033,4781~1,5983,5662,2226,0)~04,2798" ascii
    $s11 = "@yD@lt(\"0~}R<~[s@u@yD@lt(\"0~eR<~R\\\\C@j@m@j~=@rs@z@uud@m(~;break;case ~(2909,361,71~=(9796,5513,~102,4509,1))~@qdvk@rq@v@y~RC" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}