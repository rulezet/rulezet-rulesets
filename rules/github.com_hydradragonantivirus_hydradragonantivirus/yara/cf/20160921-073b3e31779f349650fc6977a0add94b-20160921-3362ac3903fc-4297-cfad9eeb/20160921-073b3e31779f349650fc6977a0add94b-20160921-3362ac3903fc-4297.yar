rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_3362ac3903fc_4297 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"

  strings:
    $s1 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj\";})" ascii
    $s2 = "000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\"" ascii
    $s3 = "Gn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s4 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f00" ascii
    $s5 = "tion f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}