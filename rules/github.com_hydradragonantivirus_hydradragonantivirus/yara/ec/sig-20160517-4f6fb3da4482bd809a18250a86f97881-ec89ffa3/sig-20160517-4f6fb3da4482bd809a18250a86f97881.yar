rule sig_20160517_4f6fb3da4482bd809a18250a86f97881 {
  meta:
    description = "datamaliciousorder - file 20160517_4f6fb3da4482bd809a18250a86f97881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ce386bb70f91e08683ec797917e8eb0847fddbc271d554116b26f96cb3f5e55"

  strings:
    $s1 = "var x1d='vfjcgwad3kxrriv34l hymmahskmrtipfdwoqyu3uaoz2diydinu2qguhowydfajgw3v1bkw=w3rxw\\'xvy4etn3vracm1mawnyx2ydieae4ofpyrwvuzs" ascii
    $s2 = ".CreateObject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   qjquqgif=r4+\"v\"+\"al\";   WScript.lister=5;   qjquqgif=\"\"+\"s\";   ww=2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}