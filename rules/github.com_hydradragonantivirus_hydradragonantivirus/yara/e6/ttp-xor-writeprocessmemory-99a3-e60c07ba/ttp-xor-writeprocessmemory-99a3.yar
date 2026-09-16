rule TTP_XOR_WriteProcessMemory_99a3 {
  strings:
    $key_99a3 = { ce d1 [2] fc f3 [2] fa c6 [2] d4 c6 [2] eb da }

  condition:
    any of them
}