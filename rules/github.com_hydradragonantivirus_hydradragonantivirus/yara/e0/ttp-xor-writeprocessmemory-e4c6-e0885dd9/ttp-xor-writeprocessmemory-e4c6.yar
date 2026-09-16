rule TTP_XOR_WriteProcessMemory_e4c6 {
  strings:
    $key_e4c6 = { b3 b4 [2] 81 96 [2] 87 a3 [2] a9 a3 [2] 96 bf }

  condition:
    any of them
}