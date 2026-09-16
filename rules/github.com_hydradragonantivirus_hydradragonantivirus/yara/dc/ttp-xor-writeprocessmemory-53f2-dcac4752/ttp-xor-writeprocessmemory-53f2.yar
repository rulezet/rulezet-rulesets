rule TTP_XOR_WriteProcessMemory_53f2 {
  strings:
    $key_53f2 = { 04 80 [2] 36 a2 [2] 30 97 [2] 1e 97 [2] 21 8b }

  condition:
    any of them
}