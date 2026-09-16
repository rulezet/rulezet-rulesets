rule TTP_XOR_WriteProcessMemory_a0ad {
  strings:
    $key_a0ad = { f7 df [2] c5 fd [2] c3 c8 [2] ed c8 [2] d2 d4 }

  condition:
    any of them
}