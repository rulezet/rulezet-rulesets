rule TTP_XOR_WriteProcessMemory_a198 {
  strings:
    $key_a198 = { f6 ea [2] c4 c8 [2] c2 fd [2] ec fd [2] d3 e1 }

  condition:
    any of them
}