rule TTP_XOR_WriteProcessMemory_a0c8 {
  strings:
    $key_a0c8 = { f7 ba [2] c5 98 [2] c3 ad [2] ed ad [2] d2 b1 }

  condition:
    any of them
}