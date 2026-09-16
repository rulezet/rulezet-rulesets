rule TTP_XOR_WriteProcessMemory_a6ad {
  strings:
    $key_a6ad = { f1 df [2] c3 fd [2] c5 c8 [2] eb c8 [2] d4 d4 }

  condition:
    any of them
}