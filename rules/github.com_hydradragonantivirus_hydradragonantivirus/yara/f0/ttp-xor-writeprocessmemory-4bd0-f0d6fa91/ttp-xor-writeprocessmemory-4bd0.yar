rule TTP_XOR_WriteProcessMemory_4bd0 {
  strings:
    $key_4bd0 = { 1c a2 [2] 2e 80 [2] 28 b5 [2] 06 b5 [2] 39 a9 }

  condition:
    any of them
}