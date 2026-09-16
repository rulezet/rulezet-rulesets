rule TTP_XOR_WriteProcessMemory_53f3 {
  strings:
    $key_53f3 = { 04 81 [2] 36 a3 [2] 30 96 [2] 1e 96 [2] 21 8a }

  condition:
    any of them
}