rule TTP_XOR_WriteProcessMemory_31c6 {
  strings:
    $key_31c6 = { 66 b4 [2] 54 96 [2] 52 a3 [2] 7c a3 [2] 43 bf }

  condition:
    any of them
}