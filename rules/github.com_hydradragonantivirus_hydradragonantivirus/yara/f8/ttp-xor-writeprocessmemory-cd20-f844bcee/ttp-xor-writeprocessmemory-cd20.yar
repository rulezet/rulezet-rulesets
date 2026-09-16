rule TTP_XOR_WriteProcessMemory_cd20 {
  strings:
    $key_cd20 = { 9a 52 [2] a8 70 [2] ae 45 [2] 80 45 [2] bf 59 }

  condition:
    any of them
}