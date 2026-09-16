rule TTP_XOR_WriteProcessMemory_2a96 {
  strings:
    $key_2a96 = { 7d e4 [2] 4f c6 [2] 49 f3 [2] 67 f3 [2] 58 ef }

  condition:
    any of them
}