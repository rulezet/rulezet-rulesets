rule TTP_XOR_WriteProcessMemory_99a1 {
  strings:
    $key_99a1 = { ce d3 [2] fc f1 [2] fa c4 [2] d4 c4 [2] eb d8 }

  condition:
    any of them
}