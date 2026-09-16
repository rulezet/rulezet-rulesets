rule TTP_XOR_WriteProcessMemory_79a9 {
  strings:
    $key_79a9 = { 2e db [2] 1c f9 [2] 1a cc [2] 34 cc [2] 0b d0 }

  condition:
    any of them
}