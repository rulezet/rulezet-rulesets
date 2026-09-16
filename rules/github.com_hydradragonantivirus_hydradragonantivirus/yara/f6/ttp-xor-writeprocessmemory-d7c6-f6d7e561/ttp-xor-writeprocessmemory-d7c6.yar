rule TTP_XOR_WriteProcessMemory_d7c6 {
  strings:
    $key_d7c6 = { 80 b4 [2] b2 96 [2] b4 a3 [2] 9a a3 [2] a5 bf }

  condition:
    any of them
}