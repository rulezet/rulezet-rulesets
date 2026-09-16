rule TTP_XOR_WriteProcessMemory_fe65 {
  strings:
    $key_fe65 = { a9 17 [2] 9b 35 [2] 9d 00 [2] b3 00 [2] 8c 1c }

  condition:
    any of them
}