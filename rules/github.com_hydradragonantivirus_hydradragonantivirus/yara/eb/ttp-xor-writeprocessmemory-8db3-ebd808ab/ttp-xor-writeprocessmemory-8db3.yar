rule TTP_XOR_WriteProcessMemory_8db3 {
  strings:
    $key_8db3 = { da c1 [2] e8 e3 [2] ee d6 [2] c0 d6 [2] ff ca }

  condition:
    any of them
}