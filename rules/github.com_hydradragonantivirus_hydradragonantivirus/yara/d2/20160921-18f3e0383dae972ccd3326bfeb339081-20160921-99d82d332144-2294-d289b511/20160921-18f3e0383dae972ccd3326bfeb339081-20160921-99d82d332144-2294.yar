rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_99d82d332144_2294 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1 = "(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s2 = "\"Ml\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(functi" ascii
    $s3 = "\"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(functi" ascii
    $s4 = "tion f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s5 = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f00" ascii
    $s6 = "){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})" ascii
    $s7 = "){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})" ascii
    $s8 = "00(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}