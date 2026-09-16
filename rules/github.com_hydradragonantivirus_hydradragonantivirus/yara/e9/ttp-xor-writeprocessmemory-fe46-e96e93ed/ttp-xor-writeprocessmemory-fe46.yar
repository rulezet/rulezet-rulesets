rule TTP_XOR_WriteProcessMemory_fe46 {
  strings:
    $key_fe46 = { a9 34 [2] 9b 16 [2] 9d 23 [2] b3 23 [2] 8c 3f }

  condition:
    any of them
}