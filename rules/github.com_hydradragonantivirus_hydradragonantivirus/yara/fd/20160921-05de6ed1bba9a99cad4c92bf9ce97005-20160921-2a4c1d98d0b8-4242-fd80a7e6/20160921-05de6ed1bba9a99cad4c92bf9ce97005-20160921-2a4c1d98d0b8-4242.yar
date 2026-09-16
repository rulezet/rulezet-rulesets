rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_2a4c1d98d0b8_4242 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"

  strings:
    $s1 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(fu" ascii
    $s2 = ";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s3 = "n f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s4 = "urn \"Vj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s5 = "turn \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}