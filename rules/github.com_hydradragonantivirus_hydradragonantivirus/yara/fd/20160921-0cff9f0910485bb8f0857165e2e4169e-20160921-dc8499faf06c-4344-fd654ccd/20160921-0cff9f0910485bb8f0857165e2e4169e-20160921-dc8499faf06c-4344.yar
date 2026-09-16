rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_dc8499faf06c_4344 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash3       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = " f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Z" ascii
    $s2 = "n\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s3 = "unction f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s4 = "(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s5 = "return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}