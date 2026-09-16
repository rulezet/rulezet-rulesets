rule _20160921_cae1392fd0c6da8c370b46e3e8040401_20160921_d1c97b87a698_5687 {
  meta:
    description = "datamaliciousorder - from files 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f0" ascii
    $s2 = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000()" ascii
    $s3 = "00(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\"" ascii
    $s4 = "000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn" ascii
    $s5 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}