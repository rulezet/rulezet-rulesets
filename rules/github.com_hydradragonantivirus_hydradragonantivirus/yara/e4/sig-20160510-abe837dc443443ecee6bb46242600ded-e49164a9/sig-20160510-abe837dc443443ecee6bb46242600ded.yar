rule sig_20160510_abe837dc443443ecee6bb46242600ded {
  meta:
    description = "datamaliciousorder - file 20160510_abe837dc443443ecee6bb46242600ded.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55fc7444aa045be64c40e0b11b61d19615b857626e87f8e8ac3dbbc196a6bf14"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 1N(){4 hT=1;if(5.J(hT)==0){9O=9}if(\"\\\\L\\\\M" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}