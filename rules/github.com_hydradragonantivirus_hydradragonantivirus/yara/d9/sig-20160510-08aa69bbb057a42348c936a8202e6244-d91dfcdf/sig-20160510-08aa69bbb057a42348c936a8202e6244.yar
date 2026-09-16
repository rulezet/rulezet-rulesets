rule sig_20160510_08aa69bbb057a42348c936a8202e6244 {
  meta:
    description = "datamaliciousorder - file 20160510_08aa69bbb057a42348c936a8202e6244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "479673bb0a049cfc8209ec0cdbf8e0778ab1694c87d91275cd42a32f9f1ae569"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 1e(E){4 3r=-1;if(5.13(3r)==0){4 b6=\"b7\"}c b5(j" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}