rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_694d4629e99f_3362 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash3       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"

  strings:
    $s1 = "rn \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(" ascii
    $s2 = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s3 = ";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s4 = "(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s5 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s6 = "ction fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}