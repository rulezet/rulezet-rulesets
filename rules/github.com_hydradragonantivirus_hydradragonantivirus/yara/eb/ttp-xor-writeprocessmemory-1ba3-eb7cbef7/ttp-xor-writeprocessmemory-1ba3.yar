rule TTP_XOR_WriteProcessMemory_1ba3 {
  strings:
    $key_1ba3 = { 4c d1 [2] 7e f3 [2] 78 c6 [2] 56 c6 [2] 69 da }

  condition:
    any of them
}