rule TTP_XOR_WriteProcessMemory_b7ad {
  strings:
    $key_b7ad = { e0 df [2] d2 fd [2] d4 c8 [2] fa c8 [2] c5 d4 }

  condition:
    any of them
}