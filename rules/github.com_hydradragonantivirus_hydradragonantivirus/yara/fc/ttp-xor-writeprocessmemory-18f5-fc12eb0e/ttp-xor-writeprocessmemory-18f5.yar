rule TTP_XOR_WriteProcessMemory_18f5 {
  strings:
    $key_18f5 = { 4f 87 [2] 7d a5 [2] 7b 90 [2] 55 90 [2] 6a 8c }

  condition:
    any of them
}