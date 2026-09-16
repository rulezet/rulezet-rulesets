rule TTP_XOR_WriteProcessMemory_29a9 {
  strings:
    $key_29a9 = { 7e db [2] 4c f9 [2] 4a cc [2] 64 cc [2] 5b d0 }

  condition:
    any of them
}