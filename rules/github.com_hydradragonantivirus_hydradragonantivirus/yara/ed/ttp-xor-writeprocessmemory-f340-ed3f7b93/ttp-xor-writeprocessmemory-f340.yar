rule TTP_XOR_WriteProcessMemory_f340 {
  strings:
    $key_f340 = { a4 32 [2] 96 10 [2] 90 25 [2] be 25 [2] 81 39 }

  condition:
    any of them
}