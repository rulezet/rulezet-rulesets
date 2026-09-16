rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_0fe6501a0417_3279 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_0fe6501a0417801a0e1868963016e9be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"

  strings:
    $s1 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi" ascii
    $s2 = "){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yz\";})" ascii
    $s3 = "unction f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s4 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s5 = "\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function " ascii
    $s6 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}