rule TTP_XOR_WriteProcessMemory_f584 {
  strings:
    $key_f584 = { a2 f6 [2] 90 d4 [2] 96 e1 [2] b8 e1 [2] 87 fd }

  condition:
    any of them
}