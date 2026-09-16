rule TTP_XOR_WriteProcessMemory_2ac6 {
  strings:
    $key_2ac6 = { 7d b4 [2] 4f 96 [2] 49 a3 [2] 67 a3 [2] 58 bf }

  condition:
    any of them
}