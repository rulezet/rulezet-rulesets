rule _20160921_cae1392fd0c6da8c370b46e3e8040401_20160921_e83251070761_2 {
  meta:
    description = "datamaliciousorder - from files 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash2       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1  = "on f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s2  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii
    $s3  = "n f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"" ascii
    $s4  = "urn \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nx\";})(),(fu" ascii
    $s5  = "(),(function f000(){return \"Nx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s6  = "),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Nx\";})(),(function f000()" ascii
    $s7  = "n \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(fu" ascii
    $s8  = "){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";}" ascii
    $s9  = "0(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Lo\";" ascii
    $s10 = "f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc" ascii
    $s11 = "{return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii
    $s12 = "eturn \"OUx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})()" ascii
    $s13 = "eturn \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})()," ascii
    $s14 = "tion f000(){return \"PTi\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s15 = "n f000(){return \"Ot\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"" ascii
    $s16 = " \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s17 = "turn \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(" ascii
    $s18 = "\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"NBs\";})(),(function" ascii
    $s19 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s20 = "(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}