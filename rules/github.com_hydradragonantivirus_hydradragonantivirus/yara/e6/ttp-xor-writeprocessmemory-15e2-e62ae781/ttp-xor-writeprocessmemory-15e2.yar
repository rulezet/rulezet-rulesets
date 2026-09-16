rule TTP_XOR_WriteProcessMemory_15e2 {
  strings:
    $key_15e2 = { 42 90 [2] 70 b2 [2] 76 87 [2] 58 87 [2] 67 9b }

  condition:
    any of them
}