rule TTP_XOR_WriteProcessMemory_d666 {
  strings:
    $key_d666 = { 81 14 [2] b3 36 [2] b5 03 [2] 9b 03 [2] a4 1f }

  condition:
    any of them
}