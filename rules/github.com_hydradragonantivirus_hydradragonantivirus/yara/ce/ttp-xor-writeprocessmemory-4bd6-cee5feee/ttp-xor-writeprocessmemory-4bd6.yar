rule TTP_XOR_WriteProcessMemory_4bd6 {
  strings:
    $key_4bd6 = { 1c a4 [2] 2e 86 [2] 28 b3 [2] 06 b3 [2] 39 af }

  condition:
    any of them
}