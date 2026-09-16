rule TTP_XOR_WriteProcessMemory_8da3 {
  strings:
    $key_8da3 = { da d1 [2] e8 f3 [2] ee c6 [2] c0 c6 [2] ff da }

  condition:
    any of them
}