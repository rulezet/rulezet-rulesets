rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_382a0f9b1ae6_4299 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_5e3ac68b2242250176f3300039d176f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash4       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"

  strings:
    $s1 = "nction f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retu" ascii
    $s2 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";" ascii
    $s3 = "rn \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(f" ascii
    $s4 = "Gn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(functio" ascii
    $s5 = "Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}