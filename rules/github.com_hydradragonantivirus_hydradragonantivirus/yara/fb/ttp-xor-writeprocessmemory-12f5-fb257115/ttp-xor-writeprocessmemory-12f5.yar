rule TTP_XOR_WriteProcessMemory_12f5 {
  strings:
    $key_12f5 = { 45 87 [2] 77 a5 [2] 71 90 [2] 5f 90 [2] 60 8c }

  condition:
    any of them
}