rule TTP_XOR_WriteProcessMemory_4bd2 {
  strings:
    $key_4bd2 = { 1c a0 [2] 2e 82 [2] 28 b7 [2] 06 b7 [2] 39 ab }

  condition:
    any of them
}