rule TTP_XOR_WriteProcessMemory_95d0 {
  strings:
    $key_95d0 = { c2 a2 [2] f0 80 [2] f6 b5 [2] d8 b5 [2] e7 a9 }

  condition:
    any of them
}