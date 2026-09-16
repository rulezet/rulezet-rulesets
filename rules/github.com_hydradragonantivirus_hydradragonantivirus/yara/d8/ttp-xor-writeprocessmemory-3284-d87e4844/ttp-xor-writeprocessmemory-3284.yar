rule TTP_XOR_WriteProcessMemory_3284 {
  strings:
    $key_3284 = { 65 f6 [2] 57 d4 [2] 51 e1 [2] 7f e1 [2] 40 fd }

  condition:
    any of them
}