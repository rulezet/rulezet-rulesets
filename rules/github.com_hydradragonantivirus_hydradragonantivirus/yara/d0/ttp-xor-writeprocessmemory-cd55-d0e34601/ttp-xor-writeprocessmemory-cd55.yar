rule TTP_XOR_WriteProcessMemory_cd55 {
  strings:
    $key_cd55 = { 9a 27 [2] a8 05 [2] ae 30 [2] 80 30 [2] bf 2c }

  condition:
    any of them
}