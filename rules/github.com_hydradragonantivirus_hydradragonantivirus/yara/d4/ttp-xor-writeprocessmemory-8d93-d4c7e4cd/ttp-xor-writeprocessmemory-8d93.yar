rule TTP_XOR_WriteProcessMemory_8d93 {
  strings:
    $key_8d93 = { da e1 [2] e8 c3 [2] ee f6 [2] c0 f6 [2] ff ea }

  condition:
    any of them
}