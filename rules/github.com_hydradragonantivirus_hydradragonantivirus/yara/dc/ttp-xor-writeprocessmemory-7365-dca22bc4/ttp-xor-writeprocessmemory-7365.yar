rule TTP_XOR_WriteProcessMemory_7365 {
  strings:
    $key_7365 = { 24 17 [2] 16 35 [2] 10 00 [2] 3e 00 [2] 01 1c }

  condition:
    any of them
}