rule TTP_XOR_WriteProcessMemory_6fc0 {
  strings:
    $key_6fc0 = { 38 b2 [2] 0a 90 [2] 0c a5 [2] 22 a5 [2] 1d b9 }

  condition:
    any of them
}