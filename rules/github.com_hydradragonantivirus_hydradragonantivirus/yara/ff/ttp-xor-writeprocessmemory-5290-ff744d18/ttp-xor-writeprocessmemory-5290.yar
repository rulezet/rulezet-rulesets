rule TTP_XOR_WriteProcessMemory_5290 {
  strings:
    $key_5290 = { 05 e2 [2] 37 c0 [2] 31 f5 [2] 1f f5 [2] 20 e9 }

  condition:
    any of them
}