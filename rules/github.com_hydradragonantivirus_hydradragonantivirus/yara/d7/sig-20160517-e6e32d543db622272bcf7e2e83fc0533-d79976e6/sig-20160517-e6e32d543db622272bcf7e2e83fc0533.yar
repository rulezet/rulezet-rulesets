rule sig_20160517_e6e32d543db622272bcf7e2e83fc0533 {
  meta:
    description = "datamaliciousorder - file 20160517_e6e32d543db622272bcf7e2e83fc0533.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13494eebe897e9d0cb043db21d2f857e848ea0dd11010d26f3f1940a8ef6ae0e"

  strings:
    $s1 = "var gk2v='vmhnogagpfgxrobbvt bxc3ksypamtrnlauqzlk344mrnssyqx14vvjhit4kaybairyyhd3b=unq1q\\'gjembtbcbh3czekuini4o4mid2yn4fklrumud" ascii
    $s2 = "Script.lister=5;   vi3gzxngsa=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      kj1stl11dx=287" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}