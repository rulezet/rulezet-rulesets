rule TTP_XOR_WriteProcessMemory_7d65 {
  strings:
    $key_7d65 = { 2a 17 [2] 18 35 [2] 1e 00 [2] 30 00 [2] 0f 1c }

  condition:
    any of them
}