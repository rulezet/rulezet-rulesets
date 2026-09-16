rule TTP_XOR_WriteProcessMemory_b78b {
  strings:
    $key_b78b = { e0 f9 [2] d2 db [2] d4 ee [2] fa ee [2] c5 f2 }

  condition:
    any of them
}