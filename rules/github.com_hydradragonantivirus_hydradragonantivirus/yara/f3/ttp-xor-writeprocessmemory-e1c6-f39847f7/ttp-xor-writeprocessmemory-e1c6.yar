rule TTP_XOR_WriteProcessMemory_e1c6 {
  strings:
    $key_e1c6 = { b6 b4 [2] 84 96 [2] 82 a3 [2] ac a3 [2] 93 bf }

  condition:
    any of them
}