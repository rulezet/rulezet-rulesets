rule TTP_XOR_WriteProcessMemory_b384 {
  strings:
    $key_b384 = { e4 f6 [2] d6 d4 [2] d0 e1 [2] fe e1 [2] c1 fd }

  condition:
    any of them
}