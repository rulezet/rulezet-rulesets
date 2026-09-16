rule TTP_XOR_WriteProcessMemory_b1c8 {
  strings:
    $key_b1c8 = { e6 ba [2] d4 98 [2] d2 ad [2] fc ad [2] c3 b1 }

  condition:
    any of them
}