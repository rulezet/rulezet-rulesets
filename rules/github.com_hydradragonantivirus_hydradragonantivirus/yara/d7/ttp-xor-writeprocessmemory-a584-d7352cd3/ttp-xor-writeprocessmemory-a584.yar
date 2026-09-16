rule TTP_XOR_WriteProcessMemory_a584 {
  strings:
    $key_a584 = { f2 f6 [2] c0 d4 [2] c6 e1 [2] e8 e1 [2] d7 fd }

  condition:
    any of them
}