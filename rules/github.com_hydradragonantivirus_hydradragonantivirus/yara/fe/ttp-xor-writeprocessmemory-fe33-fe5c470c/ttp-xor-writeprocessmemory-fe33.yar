rule TTP_XOR_WriteProcessMemory_fe33 {
  strings:
    $key_fe33 = { a9 41 [2] 9b 63 [2] 9d 56 [2] b3 56 [2] 8c 4a }

  condition:
    any of them
}