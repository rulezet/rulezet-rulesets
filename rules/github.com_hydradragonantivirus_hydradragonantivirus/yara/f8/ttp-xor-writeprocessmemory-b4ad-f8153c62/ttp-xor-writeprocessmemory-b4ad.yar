rule TTP_XOR_WriteProcessMemory_b4ad {
  strings:
    $key_b4ad = { e3 df [2] d1 fd [2] d7 c8 [2] f9 c8 [2] c6 d4 }

  condition:
    any of them
}