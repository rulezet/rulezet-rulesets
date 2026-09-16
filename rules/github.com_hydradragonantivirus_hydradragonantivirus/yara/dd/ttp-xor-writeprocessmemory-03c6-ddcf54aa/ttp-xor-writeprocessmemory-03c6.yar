rule TTP_XOR_WriteProcessMemory_03c6 {
  strings:
    $key_03c6 = { 54 b4 [2] 66 96 [2] 60 a3 [2] 4e a3 [2] 71 bf }

  condition:
    any of them
}