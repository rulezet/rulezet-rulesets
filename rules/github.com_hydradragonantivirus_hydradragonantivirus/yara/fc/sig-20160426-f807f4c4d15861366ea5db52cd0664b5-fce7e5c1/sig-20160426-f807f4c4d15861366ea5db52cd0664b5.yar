rule sig_20160426_f807f4c4d15861366ea5db52cd0664b5 {
  meta:
    description = "datamaliciousorder - file 20160426_f807f4c4d15861366ea5db52cd0664b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1809f9537a2602fcec551fed854092a76c96ba38b3d854d8c66a55c3a81e9a48"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('15 385(){16(1){10" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('15 385(){16(1){10" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}