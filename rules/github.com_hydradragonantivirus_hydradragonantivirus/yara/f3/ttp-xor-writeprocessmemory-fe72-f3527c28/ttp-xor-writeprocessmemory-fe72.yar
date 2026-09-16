rule TTP_XOR_WriteProcessMemory_fe72 {
  strings:
    $key_fe72 = { a9 00 [2] 9b 22 [2] 9d 17 [2] b3 17 [2] 8c 0b }

  condition:
    any of them
}