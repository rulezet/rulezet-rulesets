rule TTP_XOR_WriteProcessMemory_94c6 {
  strings:
    $key_94c6 = { c3 b4 [2] f1 96 [2] f7 a3 [2] d9 a3 [2] e6 bf }

  condition:
    any of them
}