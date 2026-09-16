rule _20160921_b86272ed73cef9077c204056df823014_20160921_e0f34764de4f_4035 {
  meta:
    description = "datamaliciousorder - from files 20160921_b86272ed73cef9077c204056df823014.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = ";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f" ascii
    $s2 = "turn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})()," ascii
    $s3 = "ion f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s4 = "\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f" ascii
    $s5 = "(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000()" ascii
    $s6 = "f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Z" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}