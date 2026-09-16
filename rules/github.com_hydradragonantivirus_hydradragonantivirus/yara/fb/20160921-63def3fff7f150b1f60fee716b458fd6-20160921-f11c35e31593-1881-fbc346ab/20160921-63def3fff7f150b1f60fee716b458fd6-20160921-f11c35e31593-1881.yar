rule _20160921_63def3fff7f150b1f60fee716b458fd6_20160921_f11c35e31593_1881 {
  meta:
    description = "datamaliciousorder - from files 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f0" ascii
    $s2  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"TKp\";})(),(fu" ascii
    $s3  = "unction f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s4  = "00(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn" ascii
    $s5  = ")(),(function f000(){return \"BMj\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s6  = "{return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})" ascii
    $s7  = "ction f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qa\";})(),(function f000(){retur" ascii
    $s8  = "Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s9  = "eturn \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s10 = "000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Km\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}