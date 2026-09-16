rule TTP_XOR_WriteProcessMemory_a9a9 {
  strings:
    $key_a9a9 = { fe db [2] cc f9 [2] ca cc [2] e4 cc [2] db d0 }

  condition:
    any of them
}