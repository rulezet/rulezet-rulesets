rule sig_20160422_15a72e19909a7990603472a5377c24da {
  meta:
    description = "datamaliciousorder - file 20160422_15a72e19909a7990603472a5377c24da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3f550eae631eee738f69a43b8caa3c7664e128c58f849a63baa31bf18a7cafe"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 3M(7N){8 2T=\"7M\";c(2T==0){8 7L=7O}g(\"7P\"){b " ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}