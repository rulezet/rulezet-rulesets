rule TTP_XOR_WriteProcessMemory_95c1 {
  strings:
    $key_95c1 = { c2 b3 [2] f0 91 [2] f6 a4 [2] d8 a4 [2] e7 b8 }

  condition:
    any of them
}