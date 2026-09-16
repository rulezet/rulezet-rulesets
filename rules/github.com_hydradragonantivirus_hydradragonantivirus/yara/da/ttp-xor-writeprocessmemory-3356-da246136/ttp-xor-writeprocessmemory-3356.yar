rule TTP_XOR_WriteProcessMemory_3356 {
  strings:
    $key_3356 = { 64 24 [2] 56 06 [2] 50 33 [2] 7e 33 [2] 41 2f }

  condition:
    any of them
}