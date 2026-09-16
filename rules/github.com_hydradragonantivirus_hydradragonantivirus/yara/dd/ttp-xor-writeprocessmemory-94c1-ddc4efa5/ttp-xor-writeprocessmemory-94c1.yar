rule TTP_XOR_WriteProcessMemory_94c1 {
  strings:
    $key_94c1 = { c3 b3 [2] f1 91 [2] f7 a4 [2] d9 a4 [2] e6 b8 }

  condition:
    any of them
}