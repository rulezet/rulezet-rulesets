rule _20160921_69015d5cf863b10983b8aa49b42d835e_20160921_7cd473b59463_5345 {
  meta:
    description = "datamaliciousorder - from files 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash3       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash4       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = " f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s2 = "turn \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(" ascii
    $s3 = "(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";}" ascii
    $s4 = "\"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(func" ascii
    $s5 = "ction f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}