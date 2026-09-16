rule TTP_XOR_WriteProcessMemory_a7be {
  strings:
    $key_a7be = { f0 cc [2] c2 ee [2] c4 db [2] ea db [2] d5 c7 }

  condition:
    any of them
}