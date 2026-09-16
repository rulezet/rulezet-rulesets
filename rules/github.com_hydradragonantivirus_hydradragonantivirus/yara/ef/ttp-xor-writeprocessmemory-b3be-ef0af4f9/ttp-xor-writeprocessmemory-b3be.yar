rule TTP_XOR_WriteProcessMemory_b3be {
  strings:
    $key_b3be = { e4 cc [2] d6 ee [2] d0 db [2] fe db [2] c1 c7 }

  condition:
    any of them
}