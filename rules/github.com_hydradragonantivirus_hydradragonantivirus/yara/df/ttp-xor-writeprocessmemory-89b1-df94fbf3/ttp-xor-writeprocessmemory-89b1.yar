rule TTP_XOR_WriteProcessMemory_89b1 {
  strings:
    $key_89b1 = { de c3 [2] ec e1 [2] ea d4 [2] c4 d4 [2] fb c8 }

  condition:
    any of them
}