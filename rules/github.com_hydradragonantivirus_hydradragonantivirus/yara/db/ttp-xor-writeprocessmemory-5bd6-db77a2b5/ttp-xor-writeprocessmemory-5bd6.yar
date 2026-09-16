rule TTP_XOR_WriteProcessMemory_5bd6 {
  strings:
    $key_5bd6 = { 0c a4 [2] 3e 86 [2] 38 b3 [2] 16 b3 [2] 29 af }

  condition:
    any of them
}