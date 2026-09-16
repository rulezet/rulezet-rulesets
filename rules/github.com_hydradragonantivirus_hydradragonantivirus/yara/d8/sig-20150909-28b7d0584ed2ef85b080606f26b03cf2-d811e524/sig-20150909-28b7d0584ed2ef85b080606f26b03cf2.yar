rule sig_20150909_28b7d0584ed2ef85b080606f26b03cf2 {
  meta:
    description = "datamaliciousorder - file 20150909_28b7d0584ed2ef85b080606f26b03cf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe07cf7ba7343dcb993456d8ca14ac2484f0e87ac669c0ba1aeb5e0d10b51af2"

  strings:
    $x1  = "var s=Class.create({initialize:function(){}});function getMobileOSVersionInfo(){var b=navigator.userAgent.match(/iPhone OS ([\\d" ascii
    $s2  = ".console.log(\"null element passed to setElementPosition \"+e+\", \"+d+\", \"+c+\", \"+a);return}b.style.top=e+\"px\";b.style.le" ascii
    $s3  = "rn:iwork:property\",\"X:\")}function getElementsByTagNameNS(b,c,d,e){var a=null;if(b.getElementsByTagNameNS){a=b.getElementsByTa" ascii
    $s4  = " a=\"[\\\\?&]\"+b+\"=([^&#]*)\";var c=new RegExp(a);var d=c.exec(window.location.href);if(d==null){return\"\"}else{return d[1]}}" ascii
    $s5  = "]+)/)||navigator.userAgent.match(/iPad OS ([\\d_]+)/)||navigator.userAgent.match(/CPU OS ([\\d_]+)/);var c={major:0,minor:0,poin" ascii
    $s6  = "f(\"iPhone\")!=-1){return true}else{if(navigator.userAgent.indexOf(\"iPad\")!=-1){return true}else{return false}}}}function isiP" ascii
    $s7  = "{return(navigator.userAgent.indexOf(\"iPad\")!=-1)}function getUrlParameter(b){b=b.replace(/[\\[]/,\"\\\\[\").replace(/[\\]]/,\"" ascii
    $s8  = ")}}return c}function isMobileSafari(){if(navigator.userAgent.indexOf(\"iPod\")!=-1){return true}else{if(navigator.userAgent.inde" ascii
    $s9  = "var s=Class.create({initialize:function(){}});function getMobileOSVersionInfo(){var b=navigator.userAgent.match(/iPhone OS ([\\d" ascii
    $s10 = "a,A;var w=new Object();if(j.length<4){j=\"\"+(j-0+1900)}w.y=\"\"+j;w.yyyy=j;w.yy=j.substring(2,4);w.M=g;w.MM=LZ(g);w.MMM=MONTH_N" ascii
    $s11 = "rototype,{format:function(D){D=D+\"\";var I=this;var l=\"\";var v=0;var G=\"\";var f=\"\";var j=I.getFullYear()+\"\";var g=I.get" ascii
    $s12 = "AM\"}w.m=x;w.mm=LZ(x);w.s=q;w.ss=LZ(q);while(v<D.length){G=D.charAt(v);f=\"\";while((D.charAt(v)==G)&&(v<D.length)){f+=D.charAt(" ascii
    $s13 = "meNS(d,c)}else{a=b.getElementsByTagName(e+c)}return a};" fullword ascii
    $s14 = ")}if(w[f]!=null){l=l+w[f]}else{l=l+f}}return l}});function getHecklerElementsByTagName(a,b){return getElementsByTagNameNS(a,b,\"" ascii
    $s15 = "b.style.width=c+\"px\";b.style.height=a+\"px\"}function setElementRect(a,b){if(a==null){return}a.style.top=b.y;a.style.left=b.x;" ascii
    $s16 = "[g-1];w.NNN=MONTH_NAMES[g+11];w.d=F;w.dd=LZ(F);w.E=DAY_NAMES[o+7];w.EE=DAY_NAMES[o];w.H=n;w.HH=LZ(n);if(n==0){w.h=12}else{if(n>1" ascii
    $s17 = "yle.width=b.width;a.style.height=b.height}function centerElementInDiv(c,e,d,a,b){if(c==null){return}var g=(b-d)/2;var f=(a-e)/2;" ascii
    $s18 = "f.height=g*(e/c)}else{if(b<a){f.width=c*(d/g);f.height=d}else{f.width=e;f.height=d}}return f}function parseTransformMatrix(a){va" ascii
    $s19 = "setElementPosition(c,g,f,e,d)}function showElement(a){if(a==null){return}a.style.visibility=\"visible\"}function hideElement(a){" ascii
    $s20 = "\",\"Apr\",\"May\",\"Jun\",\"Jul\",\"Aug\",\"Sep\",\"Oct\",\"Nov\",\"Dec\");var DAY_NAMES=new Array(\"Sunday\",\"Monday\",\"Tues" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}