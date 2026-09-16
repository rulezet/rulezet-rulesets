rule TTP_XOR_WriteProcessMemory_4584 {
  strings:
    $key_4584 = { 12 f6 [2] 20 d4 [2] 26 e1 [2] 08 e1 [2] 37 fd }

  condition:
    any of them
}