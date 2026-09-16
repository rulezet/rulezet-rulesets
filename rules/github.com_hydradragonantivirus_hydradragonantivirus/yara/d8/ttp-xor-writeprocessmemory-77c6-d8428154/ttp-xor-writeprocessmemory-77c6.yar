rule TTP_XOR_WriteProcessMemory_77c6 {
  strings:
    $key_77c6 = { 20 b4 [2] 12 96 [2] 14 a3 [2] 3a a3 [2] 05 bf }

  condition:
    any of them
}