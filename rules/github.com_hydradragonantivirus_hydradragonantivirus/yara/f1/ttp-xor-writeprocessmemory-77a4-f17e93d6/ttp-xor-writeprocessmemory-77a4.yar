rule TTP_XOR_WriteProcessMemory_77a4 {
  strings:
    $key_77a4 = { 20 d6 [2] 12 f4 [2] 14 c1 [2] 3a c1 [2] 05 dd }

  condition:
    any of them
}