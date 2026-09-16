rule TTP_XOR_WriteProcessMemory_7bf5 {
  strings:
    $key_7bf5 = { 2c 87 [2] 1e a5 [2] 18 90 [2] 36 90 [2] 09 8c }

  condition:
    any of them
}