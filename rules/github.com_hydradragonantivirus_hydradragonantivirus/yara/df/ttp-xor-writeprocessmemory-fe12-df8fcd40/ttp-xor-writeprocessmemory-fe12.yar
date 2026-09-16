rule TTP_XOR_WriteProcessMemory_fe12 {
  strings:
    $key_fe12 = { a9 60 [2] 9b 42 [2] 9d 77 [2] b3 77 [2] 8c 6b }

  condition:
    any of them
}