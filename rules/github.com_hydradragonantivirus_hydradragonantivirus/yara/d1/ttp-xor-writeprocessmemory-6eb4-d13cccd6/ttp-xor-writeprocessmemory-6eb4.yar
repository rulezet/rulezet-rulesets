rule TTP_XOR_WriteProcessMemory_6eb4 {
  strings:
    $key_6eb4 = { 39 c6 [2] 0b e4 [2] 0d d1 [2] 23 d1 [2] 1c cd }

  condition:
    any of them
}