rule TTP_XOR_WriteProcessMemory_95f1 {
  strings:
    $key_95f1 = { c2 83 [2] f0 a1 [2] f6 94 [2] d8 94 [2] e7 88 }

  condition:
    any of them
}