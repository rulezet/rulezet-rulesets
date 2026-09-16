rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_382a0f9b1ae6_4291 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"

  strings:
    $s1 = "nction f000(){return \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s2 = "00(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn" ascii
    $s3 = "h\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f" ascii
    $s4 = "eturn \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(" ascii
    $s5 = "(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}