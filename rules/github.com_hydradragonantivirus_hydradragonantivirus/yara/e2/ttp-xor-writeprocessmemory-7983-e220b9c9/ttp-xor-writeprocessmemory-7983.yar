rule TTP_XOR_WriteProcessMemory_7983 {
  strings:
    $key_7983 = { 2e f1 [2] 1c d3 [2] 1a e6 [2] 34 e6 [2] 0b fa }

  condition:
    any of them
}