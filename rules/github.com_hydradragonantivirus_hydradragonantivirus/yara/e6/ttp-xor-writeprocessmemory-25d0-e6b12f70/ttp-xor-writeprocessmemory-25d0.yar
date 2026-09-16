rule TTP_XOR_WriteProcessMemory_25d0 {
  strings:
    $key_25d0 = { 72 a2 [2] 40 80 [2] 46 b5 [2] 68 b5 [2] 57 a9 }

  condition:
    any of them
}