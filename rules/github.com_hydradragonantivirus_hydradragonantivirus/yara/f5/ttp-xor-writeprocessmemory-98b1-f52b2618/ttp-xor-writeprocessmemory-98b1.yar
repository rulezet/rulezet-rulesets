rule TTP_XOR_WriteProcessMemory_98b1 {
  strings:
    $key_98b1 = { cf c3 [2] fd e1 [2] fb d4 [2] d5 d4 [2] ea c8 }

  condition:
    any of them
}