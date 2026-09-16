rule TTP_XOR_WriteProcessMemory_99a7 {
  strings:
    $key_99a7 = { ce d5 [2] fc f7 [2] fa c2 [2] d4 c2 [2] eb de }

  condition:
    any of them
}