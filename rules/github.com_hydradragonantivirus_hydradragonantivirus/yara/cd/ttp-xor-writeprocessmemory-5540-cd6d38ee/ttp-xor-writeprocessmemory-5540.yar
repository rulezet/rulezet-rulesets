rule TTP_XOR_WriteProcessMemory_5540 {
  strings:
    $key_5540 = { 02 32 [2] 30 10 [2] 36 25 [2] 18 25 [2] 27 39 }

  condition:
    any of them
}