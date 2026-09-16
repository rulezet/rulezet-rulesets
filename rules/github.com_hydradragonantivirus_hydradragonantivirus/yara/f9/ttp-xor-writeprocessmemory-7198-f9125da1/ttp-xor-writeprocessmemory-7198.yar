rule TTP_XOR_WriteProcessMemory_7198 {
  strings:
    $key_7198 = { 26 ea [2] 14 c8 [2] 12 fd [2] 3c fd [2] 03 e1 }

  condition:
    any of them
}