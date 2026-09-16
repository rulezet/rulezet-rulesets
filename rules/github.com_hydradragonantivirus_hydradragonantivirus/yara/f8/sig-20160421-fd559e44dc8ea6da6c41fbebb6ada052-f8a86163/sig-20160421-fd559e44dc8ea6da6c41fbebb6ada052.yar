rule sig_20160421_fd559e44dc8ea6da6c41fbebb6ada052 {
  meta:
    description = "datamaliciousorder - file 20160421_fd559e44dc8ea6da6c41fbebb6ada052.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b82066a721ccafabf8506e4d01dcba38ca65572ece970539438b19d119894b52"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 5q(73,72,71){8 5p=\"74\";c(5p===e){8 75=e}}i 3Q(" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}