rule _20160921_02b826231ece268e91633311d2c70554_20160921_2746dcb02909_4143 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_bcf3911462135150c96c6b8eccf51628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash4       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"

  strings:
    $s1 = "n \"EZu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(f" ascii
    $s2 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"B" ascii
    $s3 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"R" ascii
    $s4 = "rn \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s5 = "rn \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}