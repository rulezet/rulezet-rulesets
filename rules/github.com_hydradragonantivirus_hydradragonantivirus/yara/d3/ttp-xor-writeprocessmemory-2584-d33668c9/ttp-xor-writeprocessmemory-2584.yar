rule TTP_XOR_WriteProcessMemory_2584 {
  strings:
    $key_2584 = { 72 f6 [2] 40 d4 [2] 46 e1 [2] 68 e1 [2] 57 fd }

  condition:
    any of them
}