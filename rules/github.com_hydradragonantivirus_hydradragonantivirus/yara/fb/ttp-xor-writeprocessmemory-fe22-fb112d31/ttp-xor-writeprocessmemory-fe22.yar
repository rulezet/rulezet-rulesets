rule TTP_XOR_WriteProcessMemory_fe22 {
  strings:
    $key_fe22 = { a9 50 [2] 9b 72 [2] 9d 47 [2] b3 47 [2] 8c 5b }

  condition:
    any of them
}