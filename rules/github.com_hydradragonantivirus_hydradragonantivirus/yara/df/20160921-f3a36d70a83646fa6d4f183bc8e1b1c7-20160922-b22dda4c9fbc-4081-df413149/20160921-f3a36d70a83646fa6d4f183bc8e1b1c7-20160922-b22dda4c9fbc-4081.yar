rule _20160921_f3a36d70a83646fa6d4f183bc8e1b1c7_20160922_b22dda4c9fbc_4081 {
  meta:
    description = "datamaliciousorder - from files 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";}" ascii
    $s2 = "on f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s3 = " f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"X" ascii
    $s4 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s5 = "eturn \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})()," ascii
    $s6 = "on f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}