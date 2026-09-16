rule TTP_XOR_WriteProcessMemory_fe32 {
  strings:
    $key_fe32 = { a9 40 [2] 9b 62 [2] 9d 57 [2] b3 57 [2] 8c 4b }

  condition:
    any of them
}