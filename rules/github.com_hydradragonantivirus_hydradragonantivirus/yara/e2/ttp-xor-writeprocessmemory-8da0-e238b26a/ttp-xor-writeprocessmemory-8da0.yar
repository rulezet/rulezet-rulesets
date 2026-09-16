rule TTP_XOR_WriteProcessMemory_8da0 {
  strings:
    $key_8da0 = { da d2 [2] e8 f0 [2] ee c5 [2] c0 c5 [2] ff d9 }

  condition:
    any of them
}