rule TTP_XOR_WriteProcessMemory_51c6 {
  strings:
    $key_51c6 = { 06 b4 [2] 34 96 [2] 32 a3 [2] 1c a3 [2] 23 bf }

  condition:
    any of them
}