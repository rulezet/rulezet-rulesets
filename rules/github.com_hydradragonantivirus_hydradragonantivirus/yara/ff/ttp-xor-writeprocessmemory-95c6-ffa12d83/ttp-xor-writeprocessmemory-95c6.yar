rule TTP_XOR_WriteProcessMemory_95c6 {
  strings:
    $key_95c6 = { c2 b4 [2] f0 96 [2] f6 a3 [2] d8 a3 [2] e7 bf }

  condition:
    any of them
}