rule TTP_XOR_WriteProcessMemory_83c6 {
  strings:
    $key_83c6 = { d4 b4 [2] e6 96 [2] e0 a3 [2] ce a3 [2] f1 bf }

  condition:
    any of them
}