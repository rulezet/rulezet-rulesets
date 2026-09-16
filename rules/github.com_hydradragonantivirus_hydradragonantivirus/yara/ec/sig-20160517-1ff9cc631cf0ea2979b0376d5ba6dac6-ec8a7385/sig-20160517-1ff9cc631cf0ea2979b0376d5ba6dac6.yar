rule sig_20160517_1ff9cc631cf0ea2979b0376d5ba6dac6 {
  meta:
    description = "datamaliciousorder - file 20160517_1ff9cc631cf0ea2979b0376d5ba6dac6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bcaf66a4394a16281a0a3d53fd3d2487d03be8c621164643697d4da44948e59"

  strings:
    $s1 = "var x1d='vfjcgwad3kxrriv34l hymmahskmrtipfdwoqyu3uaoz2diydinu2qguhowydfajgw3v1bkw=w3rxw\\'xvy4etn3vracm1mawnyx2ydieae4ofpyrwvuzs" ascii
    $s2 = ".CreateObject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   qjquqgif=r4+\"v\"+\"al\";   WScript.lister=5;   qjquqgif=\"\"+\"s\";   ww=2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}