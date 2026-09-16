rule TTP_XOR_WriteProcessMemory_94c0 {
  strings:
    $key_94c0 = { c3 b2 [2] f1 90 [2] f7 a5 [2] d9 a5 [2] e6 b9 }

  condition:
    any of them
}