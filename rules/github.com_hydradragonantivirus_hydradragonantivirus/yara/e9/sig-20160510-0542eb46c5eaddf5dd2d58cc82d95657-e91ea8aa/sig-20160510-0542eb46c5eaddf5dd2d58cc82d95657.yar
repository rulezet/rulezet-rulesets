rule sig_20160510_0542eb46c5eaddf5dd2d58cc82d95657 {
  meta:
    description = "datamaliciousorder - file 20160510_0542eb46c5eaddf5dd2d58cc82d95657.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f144cd82a6417f33374d4c6cc0d05eaeb44eb959782b3ddbdfd2c636873925f8"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c Q(1f,17,18,1o){if(\"9C\".j>=7(-9D)){eP=\\'\\'}4 " ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}