rule TTP_XOR_WriteProcessMemory_92c6 {
  strings:
    $key_92c6 = { c5 b4 [2] f7 96 [2] f1 a3 [2] df a3 [2] e0 bf }

  condition:
    any of them
}