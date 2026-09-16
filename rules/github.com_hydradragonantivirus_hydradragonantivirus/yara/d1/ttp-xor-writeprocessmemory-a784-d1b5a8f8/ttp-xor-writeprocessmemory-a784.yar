rule TTP_XOR_WriteProcessMemory_a784 {
  strings:
    $key_a784 = { f0 f6 [2] c2 d4 [2] c4 e1 [2] ea e1 [2] d5 fd }

  condition:
    any of them
}