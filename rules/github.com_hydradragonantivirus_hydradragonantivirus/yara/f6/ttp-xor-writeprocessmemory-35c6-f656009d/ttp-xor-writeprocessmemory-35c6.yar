rule TTP_XOR_WriteProcessMemory_35c6 {
  strings:
    $key_35c6 = { 62 b4 [2] 50 96 [2] 56 a3 [2] 78 a3 [2] 47 bf }

  condition:
    any of them
}