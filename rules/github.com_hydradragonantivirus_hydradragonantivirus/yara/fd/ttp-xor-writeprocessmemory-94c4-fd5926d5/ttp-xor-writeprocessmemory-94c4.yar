rule TTP_XOR_WriteProcessMemory_94c4 {
  strings:
    $key_94c4 = { c3 b6 [2] f1 94 [2] f7 a1 [2] d9 a1 [2] e6 bd }

  condition:
    any of them
}