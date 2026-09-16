rule _20160921_d74d6a32efd0c1fd568c81769c75b5f0_20160921_e0f34764de4f_5710 {
  meta:
    description = "datamaliciousorder - from files 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "ion f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s2 = "on f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s3 = "(function f000(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s4 = "000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj" ascii
    $s5 = "})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}