rule TTP_XOR_WriteProcessMemory_77f5 {
  strings:
    $key_77f5 = { 20 87 [2] 12 a5 [2] 14 90 [2] 3a 90 [2] 05 8c }

  condition:
    any of them
}