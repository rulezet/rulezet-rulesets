rule TTP_XOR_WriteProcessMemory_7e90 {
  strings:
    $key_7e90 = { 29 e2 [2] 1b c0 [2] 1d f5 [2] 33 f5 [2] 0c e9 }

  condition:
    any of them
}