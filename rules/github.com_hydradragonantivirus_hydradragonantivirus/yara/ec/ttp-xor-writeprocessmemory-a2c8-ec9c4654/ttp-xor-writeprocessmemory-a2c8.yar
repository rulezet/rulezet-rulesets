rule TTP_XOR_WriteProcessMemory_a2c8 {
  strings:
    $key_a2c8 = { f5 ba [2] c7 98 [2] c1 ad [2] ef ad [2] d0 b1 }

  condition:
    any of them
}