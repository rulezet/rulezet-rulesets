rule TTP_XOR_WriteProcessMemory_a38b {
  strings:
    $key_a38b = { f4 f9 [2] c6 db [2] c0 ee [2] ee ee [2] d1 f2 }

  condition:
    any of them
}