rule TTP_XOR_WriteProcessMemory_46e2 {
  strings:
    $key_46e2 = { 11 90 [2] 23 b2 [2] 25 87 [2] 0b 87 [2] 34 9b }

  condition:
    any of them
}