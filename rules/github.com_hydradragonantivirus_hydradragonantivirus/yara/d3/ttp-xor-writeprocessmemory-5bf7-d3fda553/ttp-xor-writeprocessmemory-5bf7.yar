rule TTP_XOR_WriteProcessMemory_5bf7 {
  strings:
    $key_5bf7 = { 0c 85 [2] 3e a7 [2] 38 92 [2] 16 92 [2] 29 8e }

  condition:
    any of them
}