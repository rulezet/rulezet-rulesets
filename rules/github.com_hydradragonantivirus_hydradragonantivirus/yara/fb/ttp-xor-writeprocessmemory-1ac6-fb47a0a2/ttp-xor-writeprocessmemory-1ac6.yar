rule TTP_XOR_WriteProcessMemory_1ac6 {
  strings:
    $key_1ac6 = { 4d b4 [2] 7f 96 [2] 79 a3 [2] 57 a3 [2] 68 bf }

  condition:
    any of them
}