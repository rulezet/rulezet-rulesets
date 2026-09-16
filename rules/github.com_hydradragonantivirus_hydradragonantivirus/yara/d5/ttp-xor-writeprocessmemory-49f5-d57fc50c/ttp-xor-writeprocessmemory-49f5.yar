rule TTP_XOR_WriteProcessMemory_49f5 {
  strings:
    $key_49f5 = { 1e 87 [2] 2c a5 [2] 2a 90 [2] 04 90 [2] 3b 8c }

  condition:
    any of them
}