rule TTP_XOR_WriteProcessMemory_77f7 {
  strings:
    $key_77f7 = { 20 85 [2] 12 a7 [2] 14 92 [2] 3a 92 [2] 05 8e }

  condition:
    any of them
}