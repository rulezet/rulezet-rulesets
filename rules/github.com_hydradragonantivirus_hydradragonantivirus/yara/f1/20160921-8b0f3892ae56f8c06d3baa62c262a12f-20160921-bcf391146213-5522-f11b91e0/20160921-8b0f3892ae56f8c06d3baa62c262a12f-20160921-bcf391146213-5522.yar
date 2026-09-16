rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_bcf391146213_5522 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash3       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";" ascii
    $s2 = "Zu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functi" ascii
    $s3 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\"" ascii
    $s4 = "OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s5 = "HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}