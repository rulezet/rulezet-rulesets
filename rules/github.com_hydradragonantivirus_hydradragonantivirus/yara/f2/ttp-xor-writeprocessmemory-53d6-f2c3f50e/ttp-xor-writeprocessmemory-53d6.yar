rule TTP_XOR_WriteProcessMemory_53d6 {
  strings:
    $key_53d6 = { 04 a4 [2] 36 86 [2] 30 b3 [2] 1e b3 [2] 21 af }

  condition:
    any of them
}