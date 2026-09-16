rule sig_20160510_813059e92bc11f87f5e0f20ee5248303 {
  meta:
    description = "datamaliciousorder - file 20160510_813059e92bc11f87f5e0f20ee5248303.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a73e78985e0b4ac34477709dec11b60e6d291414f47c708a21535d3edc480a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b 9n(21,1X){4 3l=-1;if(6.f(3l)>0){9o=a}if(\"9m\".i" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}