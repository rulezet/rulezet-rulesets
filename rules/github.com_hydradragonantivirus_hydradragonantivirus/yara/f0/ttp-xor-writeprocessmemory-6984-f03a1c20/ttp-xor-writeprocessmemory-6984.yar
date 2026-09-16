rule TTP_XOR_WriteProcessMemory_6984 {
  strings:
    $key_6984 = { 3e f6 [2] 0c d4 [2] 0a e1 [2] 24 e1 [2] 1b fd }

  condition:
    any of them
}