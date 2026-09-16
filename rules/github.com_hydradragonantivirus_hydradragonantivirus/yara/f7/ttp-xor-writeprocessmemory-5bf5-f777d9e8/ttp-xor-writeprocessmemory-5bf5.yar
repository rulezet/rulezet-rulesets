rule TTP_XOR_WriteProcessMemory_5bf5 {
  strings:
    $key_5bf5 = { 0c 87 [2] 3e a5 [2] 38 90 [2] 16 90 [2] 29 8c }

  condition:
    any of them
}