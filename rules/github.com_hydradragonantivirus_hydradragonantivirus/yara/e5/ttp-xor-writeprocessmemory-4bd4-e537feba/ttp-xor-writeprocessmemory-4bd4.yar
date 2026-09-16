rule TTP_XOR_WriteProcessMemory_4bd4 {
  strings:
    $key_4bd4 = { 1c a6 [2] 2e 84 [2] 28 b1 [2] 06 b1 [2] 39 ad }

  condition:
    any of them
}