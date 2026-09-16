rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160921_e0f34764de4f_3686 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh" ascii
    $s2 = " f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s3 = " f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Q" ascii
    $s4 = "p\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function " ascii
    $s5 = "\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function" ascii
    $s6 = "n \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}