rule TTP_XOR_WriteProcessMemory_fe10 {
  strings:
    $key_fe10 = { a9 62 [2] 9b 40 [2] 9d 75 [2] b3 75 [2] 8c 69 }

  condition:
    any of them
}