rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_2746dcb02909_4561 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"

  strings:
    $s1 = "function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s2 = "000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XT" ascii
    $s3 = "urn \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})()," ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii
    $s5 = "n f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}