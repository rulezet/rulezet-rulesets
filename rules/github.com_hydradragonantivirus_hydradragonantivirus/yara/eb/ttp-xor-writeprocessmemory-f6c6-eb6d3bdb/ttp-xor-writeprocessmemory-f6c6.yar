rule TTP_XOR_WriteProcessMemory_f6c6 {
  strings:
    $key_f6c6 = { a1 b4 [2] 93 96 [2] 95 a3 [2] bb a3 [2] 84 bf }

  condition:
    any of them
}