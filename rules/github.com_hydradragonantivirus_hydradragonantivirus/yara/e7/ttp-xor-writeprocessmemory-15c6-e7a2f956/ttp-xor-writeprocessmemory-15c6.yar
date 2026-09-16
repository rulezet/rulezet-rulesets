rule TTP_XOR_WriteProcessMemory_15c6 {
  strings:
    $key_15c6 = { 42 b4 [2] 70 96 [2] 76 a3 [2] 58 a3 [2] 67 bf }

  condition:
    any of them
}