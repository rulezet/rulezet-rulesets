rule TTP_XOR_WriteProcessMemory_6fc6 {
  strings:
    $key_6fc6 = { 38 b4 [2] 0a 96 [2] 0c a3 [2] 22 a3 [2] 1d bf }

  condition:
    any of them
}