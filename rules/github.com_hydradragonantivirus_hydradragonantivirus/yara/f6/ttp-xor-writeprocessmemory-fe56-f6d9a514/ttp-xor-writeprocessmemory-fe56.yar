rule TTP_XOR_WriteProcessMemory_fe56 {
  strings:
    $key_fe56 = { a9 24 [2] 9b 06 [2] 9d 33 [2] b3 33 [2] 8c 2f }

  condition:
    any of them
}