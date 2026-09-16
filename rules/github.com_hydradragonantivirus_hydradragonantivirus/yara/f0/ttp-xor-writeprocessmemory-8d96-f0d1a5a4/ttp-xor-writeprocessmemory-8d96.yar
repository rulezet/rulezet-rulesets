rule TTP_XOR_WriteProcessMemory_8d96 {
  strings:
    $key_8d96 = { da e4 [2] e8 c6 [2] ee f3 [2] c0 f3 [2] ff ef }

  condition:
    any of them
}