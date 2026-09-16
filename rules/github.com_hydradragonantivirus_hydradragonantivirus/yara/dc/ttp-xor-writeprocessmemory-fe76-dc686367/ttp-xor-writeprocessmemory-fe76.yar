rule TTP_XOR_WriteProcessMemory_fe76 {
  strings:
    $key_fe76 = { a9 04 [2] 9b 26 [2] 9d 13 [2] b3 13 [2] 8c 0f }

  condition:
    any of them
}