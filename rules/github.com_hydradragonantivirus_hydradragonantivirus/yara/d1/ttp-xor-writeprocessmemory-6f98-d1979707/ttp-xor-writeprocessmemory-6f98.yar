rule TTP_XOR_WriteProcessMemory_6f98 {
  strings:
    $key_6f98 = { 38 ea [2] 0a c8 [2] 0c fd [2] 22 fd [2] 1d e1 }

  condition:
    any of them
}