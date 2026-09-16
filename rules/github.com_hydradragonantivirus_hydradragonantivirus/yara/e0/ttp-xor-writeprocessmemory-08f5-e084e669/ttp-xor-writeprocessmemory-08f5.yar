rule TTP_XOR_WriteProcessMemory_08f5 {
  strings:
    $key_08f5 = { 5f 87 [2] 6d a5 [2] 6b 90 [2] 45 90 [2] 7a 8c }

  condition:
    any of them
}