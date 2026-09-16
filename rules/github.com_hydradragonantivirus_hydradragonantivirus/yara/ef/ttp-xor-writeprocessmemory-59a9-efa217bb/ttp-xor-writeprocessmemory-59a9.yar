rule TTP_XOR_WriteProcessMemory_59a9 {
  strings:
    $key_59a9 = { 0e db [2] 3c f9 [2] 3a cc [2] 14 cc [2] 2b d0 }

  condition:
    any of them
}