rule TTP_XOR_WriteProcessMemory_4ba3 {
  strings:
    $key_4ba3 = { 1c d1 [2] 2e f3 [2] 28 c6 [2] 06 c6 [2] 39 da }

  condition:
    any of them
}