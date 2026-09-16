rule TTP_XOR_WriteProcessMemory_11f5 {
  strings:
    $key_11f5 = { 46 87 [2] 74 a5 [2] 72 90 [2] 5c 90 [2] 63 8c }

  condition:
    any of them
}