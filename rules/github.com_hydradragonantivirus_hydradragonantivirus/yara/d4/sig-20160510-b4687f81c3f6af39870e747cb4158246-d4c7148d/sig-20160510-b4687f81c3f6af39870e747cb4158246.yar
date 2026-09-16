rule sig_20160510_b4687f81c3f6af39870e747cb4158246 {
  meta:
    description = "datamaliciousorder - file 20160510_b4687f81c3f6af39870e747cb4158246.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57a2c2fd13b070a0da41194119a2d733256b91981054bcd98b2a8e71c942d027"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 4R(f,z,17,1o){if(\"\".13(\"\\\\P\\\\P\\\\o\\\\t" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}