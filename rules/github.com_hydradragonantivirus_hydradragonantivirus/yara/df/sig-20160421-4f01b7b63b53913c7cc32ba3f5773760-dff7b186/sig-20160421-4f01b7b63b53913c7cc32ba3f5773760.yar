rule sig_20160421_4f01b7b63b53913c7cc32ba3f5773760 {
  meta:
    description = "datamaliciousorder - file 20160421_4f01b7b63b53913c7cc32ba3f5773760.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fa2f3353864d0bb7f40301409bdac2e5e8769132ad66c589fea617e07519a31"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 4R(4K,48){g(\"0\"){8 e:6 4S=\"6L\";b(4S===\"0\")" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}