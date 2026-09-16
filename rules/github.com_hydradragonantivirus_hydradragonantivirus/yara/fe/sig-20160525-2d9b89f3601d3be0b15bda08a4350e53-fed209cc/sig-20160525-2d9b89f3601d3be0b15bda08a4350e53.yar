rule sig_20160525_2d9b89f3601d3be0b15bda08a4350e53 {
  meta:
    description = "datamaliciousorder - file 20160525_2d9b89f3601d3be0b15bda08a4350e53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48fb8fc427bea7bb8d34d6856d2bf0011eedc881b87f62af834961ea49307d66"

  strings:
    $s1 = "dark(]ime + rerednere + cthe + tsilslianbmuhtoe[tpircSW = eixodb rav    \\n{\\n)rerednera ,ssorcaa(suidarelcitrap noitcnuf\\n\\n" ascii
    $s2 = "\\n;\"56x\\\\\" = rerednerr rav\\n;\"r16x\\\\h34x\\\\\" = imr rav\\n;\"47x\\\\e37x\\\\\" = eixods rav\\n;\"e07x\\\\o\" = suidare" ascii
    $s3 = "dari nruter{)gedotdari(mi noitcnuf;};dnenoisilloci nruter{)dnenoisilloci(suidarelcitrapi noitcnuf;};gsmi nruter{)gsmi(eixodi noi" ascii
    $s4 = "f rav\\n;\"c6x\\\\l\" = ecapsetihwxelff rav;};tsilslianbmuhtof nruter{)tsilslianbmuhtof(ssorcaf noitcnuf;};sdnetf nruter{)sdnetf" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}