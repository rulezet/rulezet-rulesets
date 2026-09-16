rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_a3beeaf53744_4588 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash3       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = "00(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa" ascii
    $s2 = "(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s3 = "function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5 = "rn \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}