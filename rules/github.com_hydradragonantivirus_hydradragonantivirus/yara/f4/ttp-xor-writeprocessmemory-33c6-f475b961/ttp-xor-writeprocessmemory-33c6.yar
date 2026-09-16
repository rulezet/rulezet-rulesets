rule TTP_XOR_WriteProcessMemory_33c6 {
  strings:
    $key_33c6 = { 64 b4 [2] 56 96 [2] 50 a3 [2] 7e a3 [2] 41 bf }

  condition:
    any of them
}