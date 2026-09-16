rule TTP_XOR_WriteProcessMemory_1a96 {
  strings:
    $key_1a96 = { 4d e4 [2] 7f c6 [2] 79 f3 [2] 57 f3 [2] 68 ef }

  condition:
    any of them
}