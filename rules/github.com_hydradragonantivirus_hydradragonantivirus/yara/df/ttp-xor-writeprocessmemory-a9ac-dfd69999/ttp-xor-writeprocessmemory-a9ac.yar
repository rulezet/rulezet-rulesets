rule TTP_XOR_WriteProcessMemory_a9ac {
  strings:
    $key_a9ac = { fe de [2] cc fc [2] ca c9 [2] e4 c9 [2] db d5 }

  condition:
    any of them
}