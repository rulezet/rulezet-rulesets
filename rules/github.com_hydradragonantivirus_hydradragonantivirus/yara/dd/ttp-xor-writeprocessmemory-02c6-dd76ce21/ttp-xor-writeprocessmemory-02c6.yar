rule TTP_XOR_WriteProcessMemory_02c6 {
  strings:
    $key_02c6 = { 55 b4 [2] 67 96 [2] 61 a3 [2] 4f a3 [2] 70 bf }

  condition:
    any of them
}