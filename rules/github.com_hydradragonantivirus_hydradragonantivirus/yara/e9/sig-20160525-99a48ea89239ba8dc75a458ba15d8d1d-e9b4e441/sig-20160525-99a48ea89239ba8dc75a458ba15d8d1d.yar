rule sig_20160525_99a48ea89239ba8dc75a458ba15d8d1d {
  meta:
    description = "datamaliciousorder - file 20160525_99a48ea89239ba8dc75a458ba15d8d1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaf6227300979baab4f086d204cd13c09348358e63849a0fce4a77a4f5f9204e"

  strings:
    $s1 = " nruter{)(gsme noitcnuf( + imd+tsilslianbmuhtod + )ssorcad(cthd+sdnetd + deerdd+)keppeld(ecapsetihwxelfd+gedotdard+md+)gsmd(suid" ascii
    $s2 = "[tpircSW = eixodb rav    \\n{\\n)rerednera ,ssorcaa(suidarelcitrap noitcnuf\\n\\n\\n;}\\n;)gedotdara(dnenoisilloc nruter    \\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}