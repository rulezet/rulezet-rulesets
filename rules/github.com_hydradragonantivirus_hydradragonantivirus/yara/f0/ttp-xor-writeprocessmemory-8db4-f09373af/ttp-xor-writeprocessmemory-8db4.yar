rule TTP_XOR_WriteProcessMemory_8db4 {
  strings:
    $key_8db4 = { da c6 [2] e8 e4 [2] ee d1 [2] c0 d1 [2] ff cd }

  condition:
    any of them
}