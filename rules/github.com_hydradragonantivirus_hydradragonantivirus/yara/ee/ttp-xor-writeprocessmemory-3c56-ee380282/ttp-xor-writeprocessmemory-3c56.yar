rule TTP_XOR_WriteProcessMemory_3c56 {
  strings:
    $key_3c56 = { 6b 24 [2] 59 06 [2] 5f 33 [2] 71 33 [2] 4e 2f }

  condition:
    any of them
}