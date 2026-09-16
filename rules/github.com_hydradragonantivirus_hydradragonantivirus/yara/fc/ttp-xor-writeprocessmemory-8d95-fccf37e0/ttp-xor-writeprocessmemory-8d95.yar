rule TTP_XOR_WriteProcessMemory_8d95 {
  strings:
    $key_8d95 = { da e7 [2] e8 c5 [2] ee f0 [2] c0 f0 [2] ff ec }

  condition:
    any of them
}