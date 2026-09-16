rule TTP_XOR_WriteProcessMemory_6498 {
  strings:
    $key_6498 = { 33 ea [2] 01 c8 [2] 07 fd [2] 29 fd [2] 16 e1 }

  condition:
    any of them
}