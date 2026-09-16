rule sig_826d51f05f41859d3268b7e1591c3b986d1c7fb0ff15bf411019309a7506 {
  meta:
    description = "datamaliciousorder - file 826d51f05f41859d3268b7e1591c3b986d1c7fb0ff15bf411019309a7506e776.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "826d51f05f41859d3268b7e1591c3b986d1c7fb0ff15bf411019309a7506e776"

  strings:
    $s1  = "(function(c,d){var r=b,e=c();while(!![]){try{var f=parseInt(r(0x19a,'z7fh'))/0x1+parseInt(r(0x1a3,'UTY)'))/0x2+parseInt(r(0x187," ascii
    $s2  = "](),c['Run']('\\x22'+q+'\\x22',0x1,![]);break;}o[w(0x18f,'SciG')]();}}try{k(g,h)&&(l(h,i)&&(WScript[s(0x19c,'o[Yb')](0x5dc),m(i)" ascii
    $s3  = "ar v=s,p=WScript[v(0x19e,'Yd%s')](v(0x19b,'2i(T')),q=p['NameSpace'](n);if(!q)return![];if(!d[v(0x186,'z7fh')](o))d[v(0x175,'yHGj" ascii
    $s4  = "90b),(function(){var s=b,c=WScript['CreateObject'](s(0x17d,'fXgn')),d=WScript['CreateObject'](s(0x179,'xv!Z')),f=c['ExpandEnviro" ascii
    $s5  = "w=p['length'];v<w;v++){q+='%'+('00'+p['charCodeAt'](v)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(q);};var m=f" ascii
    $s6  = "(0x184,'dG!u')]));}return p;}function k(n,o){var u=s,p=new ActiveXObject('MSXML2.XMLHTTP');p[u(0x188,'l09R')](u(0x183,'@V]U'),n," ascii
    $s7  = "tion j(n){var t=s,o=t(0x180,'C8kx'),p='';for(var q=0x0;q<n;q++){p+=o[t(0x195,'yHGj')](Math[t(0x1a6,'xv!Z')](Math['random']()*o[t" ascii
    $s8  = "![]),p[u(0x17f,'UOla')]();if(p[u(0x1a2,'(^j8')]!==0xc8)return![];var q=new ActiveXObject('ADODB.Stream');return q['Type']=0x1,q[" ascii
    $s9  = "(0x1a0,'0UYj')](n)[w(0x198,'WamQ')]);while(!o[w(0x1a1,'UTY)')]()){var p=o[w(0x17e,'ABGi')]();if(d[w(0x17b,'(r][')](p[w(0x1a8,'En" ascii
    $s10 = "')](o);return p[v(0x178,'xv!Z')](o)[v(0x1a4,'*vJZ')](q[v(0x181,'k^g^')](),0x14),!![];}function m(n){var w=s,o=new Enumerator(d[w" ascii
    $s11 = ";},b(c,d);}function a(){var x=['W7eVWOXR','iIegW7S','WQ0aC3VcG8ogW5tcTSooWPj9WOjnbSkdWOJdLmkMW5JdVmkTW4tdRfiYDbD+WRShW6ZdH0RcHSk" ascii
    $s12 = "[u],p[u]=p[q],p[q]=r,t+=String['fromCharCode'](n['charCodeAt'](v)^p[(p[u]+p[q])%0x100]);}return t;};b['xUHguN']=m,c=arguments,b[" ascii
    $s13 = "u(0x176,'[arY')](),q[u(0x196,'o[Yb')](p[u(0x199,'WsLG')]),q[u(0x190,'8XQK')](o,0x2),q[u(0x18c,'fXgn')](),!![];}function l(n,o){v" ascii
    $s14 = "(function(c,d){var r=b,e=c();while(!![]){try{var f=parseInt(r(0x19a,'z7fh'))/0x1+parseInt(r(0x1a3,'UTY)'))/0x2+parseInt(r(0x187," ascii
    $s15 = "'soFvDk']=!![];}var j=e[0x0],k=f+j,l=c[k];return!l?(b['kpGdur']===undefined&&(b['kpGdur']=!![]),h=b['xUHguN'](h,g),c[k]=h):h=l,h" ascii
    $s16 = "8kPAmk8'];a=function(){return x;};return a();}" fullword ascii
    $s17 = "unction(n,o){var p=[],q=0x0,r,t='';n=i(n);var u;for(u=0x0;u<0x100;u++){p[u]=u;}for(u=0x0;u<0x100;u++){q=(q+p[u]+o['charCodeAt'](" ascii
    $s18 = ";}catch(n){}}()));function b(c,d){var e=a();return b=function(f,g){f=f-0x175;var h=e[f];if(b['soFvDk']===undefined){var i=functi" ascii
    $s19 = "T'))/0x7+-parseInt(r(0x19d,'EoQ!'))/0x8;if(f===d)break;else e['push'](e['shift']());}catch(g){e['push'](e['shift']());}}}(a,0x5d" ascii

  condition:
    uint16(0) == 0x6628 and
    8 of them
}