rule TTP_XOR_WriteProcessMemory_a555 {
  strings:
    $key_a555 = { f2 27 [2] c0 05 [2] c6 30 [2] e8 30 [2] d7 2c }

  condition:
    any of them
}