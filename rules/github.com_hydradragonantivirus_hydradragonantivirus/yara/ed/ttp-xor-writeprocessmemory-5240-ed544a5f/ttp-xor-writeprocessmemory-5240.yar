rule TTP_XOR_WriteProcessMemory_5240 {
  strings:
    $key_5240 = { 05 32 [2] 37 10 [2] 31 25 [2] 1f 25 [2] 20 39 }

  condition:
    any of them
}