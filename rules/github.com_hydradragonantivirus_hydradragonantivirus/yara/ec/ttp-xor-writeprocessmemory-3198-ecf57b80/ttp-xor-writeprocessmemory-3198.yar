rule TTP_XOR_WriteProcessMemory_3198 {
  strings:
    $key_3198 = { 66 ea [2] 54 c8 [2] 52 fd [2] 7c fd [2] 43 e1 }

  condition:
    any of them
}