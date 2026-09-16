rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_3551 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = "0(){return \"Ot\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";}" ascii
    $s2 = "0(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";" ascii
    $s3 = "on f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"B" ascii
    $s4 = "KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(functi" ascii
    $s5 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";}" ascii
    $s6 = " f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}