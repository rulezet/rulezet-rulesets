rule TTP_XOR_WriteProcessMemory_16c6 {
  strings:
    $key_16c6 = { 41 b4 [2] 73 96 [2] 75 a3 [2] 5b a3 [2] 64 bf }

  condition:
    any of them
}