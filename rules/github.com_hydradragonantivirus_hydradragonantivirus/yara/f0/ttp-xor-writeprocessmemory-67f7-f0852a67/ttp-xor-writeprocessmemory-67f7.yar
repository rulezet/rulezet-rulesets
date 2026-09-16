rule TTP_XOR_WriteProcessMemory_67f7 {
  strings:
    $key_67f7 = { 30 85 [2] 02 a7 [2] 04 92 [2] 2a 92 [2] 15 8e }

  condition:
    any of them
}