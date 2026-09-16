rule TTP_XOR_WriteProcessMemory_8db9 {
  strings:
    $key_8db9 = { da cb [2] e8 e9 [2] ee dc [2] c0 dc [2] ff c0 }

  condition:
    any of them
}