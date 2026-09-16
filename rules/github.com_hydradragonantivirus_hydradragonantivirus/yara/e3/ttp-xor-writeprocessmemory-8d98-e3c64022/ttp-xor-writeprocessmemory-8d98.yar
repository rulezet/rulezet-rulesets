rule TTP_XOR_WriteProcessMemory_8d98 {
  strings:
    $key_8d98 = { da ea [2] e8 c8 [2] ee fd [2] c0 fd [2] ff e1 }

  condition:
    any of them
}