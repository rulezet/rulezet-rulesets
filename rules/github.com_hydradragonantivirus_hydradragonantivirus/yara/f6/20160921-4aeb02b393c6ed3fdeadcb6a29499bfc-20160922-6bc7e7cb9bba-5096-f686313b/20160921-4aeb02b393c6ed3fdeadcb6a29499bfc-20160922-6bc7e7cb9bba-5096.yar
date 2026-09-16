rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160922_6bc7e7cb9bba_5096 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})" ascii
    $s2 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f0" ascii
    $s3 = "tion f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s5 = "\"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}