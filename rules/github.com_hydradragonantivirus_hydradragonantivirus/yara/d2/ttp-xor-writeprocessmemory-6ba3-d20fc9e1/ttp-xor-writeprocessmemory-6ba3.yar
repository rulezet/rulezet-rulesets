rule TTP_XOR_WriteProcessMemory_6ba3 {
  strings:
    $key_6ba3 = { 3c d1 [2] 0e f3 [2] 08 c6 [2] 26 c6 [2] 19 da }

  condition:
    any of them
}