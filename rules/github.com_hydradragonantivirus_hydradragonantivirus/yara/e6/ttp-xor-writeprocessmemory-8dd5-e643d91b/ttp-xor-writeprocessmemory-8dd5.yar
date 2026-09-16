rule TTP_XOR_WriteProcessMemory_8dd5 {
  strings:
    $key_8dd5 = { da a7 [2] e8 85 [2] ee b0 [2] c0 b0 [2] ff ac }

  condition:
    any of them
}