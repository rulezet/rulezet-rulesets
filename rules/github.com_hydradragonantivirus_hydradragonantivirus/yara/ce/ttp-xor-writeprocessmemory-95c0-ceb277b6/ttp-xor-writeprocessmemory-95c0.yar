rule TTP_XOR_WriteProcessMemory_95c0 {
  strings:
    $key_95c0 = { c2 b2 [2] f0 90 [2] f6 a5 [2] d8 a5 [2] e7 b9 }

  condition:
    any of them
}