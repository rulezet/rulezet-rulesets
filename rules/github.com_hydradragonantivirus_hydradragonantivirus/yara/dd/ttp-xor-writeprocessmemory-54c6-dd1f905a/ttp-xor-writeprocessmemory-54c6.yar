rule TTP_XOR_WriteProcessMemory_54c6 {
  strings:
    $key_54c6 = { 03 b4 [2] 31 96 [2] 37 a3 [2] 19 a3 [2] 26 bf }

  condition:
    any of them
}