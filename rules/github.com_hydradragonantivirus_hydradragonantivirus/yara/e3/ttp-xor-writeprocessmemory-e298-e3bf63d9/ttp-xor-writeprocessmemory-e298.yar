rule TTP_XOR_WriteProcessMemory_e298 {
  strings:
    $key_e298 = { b5 ea [2] 87 c8 [2] 81 fd [2] af fd [2] 90 e1 }

  condition:
    any of them
}