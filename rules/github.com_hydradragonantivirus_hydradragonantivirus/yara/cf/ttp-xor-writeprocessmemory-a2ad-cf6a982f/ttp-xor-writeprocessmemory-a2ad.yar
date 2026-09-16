rule TTP_XOR_WriteProcessMemory_a2ad {
  strings:
    $key_a2ad = { f5 df [2] c7 fd [2] c1 c8 [2] ef c8 [2] d0 d4 }

  condition:
    any of them
}