rule TTP_XOR_WriteProcessMemory_a751 {
  strings:
    $key_a751 = { f0 23 [2] c2 01 [2] c4 34 [2] ea 34 [2] d5 28 }

  condition:
    any of them
}