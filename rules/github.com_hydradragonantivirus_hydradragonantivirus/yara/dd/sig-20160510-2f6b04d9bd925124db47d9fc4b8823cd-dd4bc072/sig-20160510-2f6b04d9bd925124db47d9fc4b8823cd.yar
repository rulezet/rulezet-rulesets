rule sig_20160510_2f6b04d9bd925124db47d9fc4b8823cd {
  meta:
    description = "datamaliciousorder - file 20160510_2f6b04d9bd925124db47d9fc4b8823cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ed4ba2247901a578c92746af60f0ba03575fcedbfb500c23eb426a39c3f57f"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('g s(q){4 4j=0;if(6.G(4j)===0){U=\"9H\"}5{9I=9}if(" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}