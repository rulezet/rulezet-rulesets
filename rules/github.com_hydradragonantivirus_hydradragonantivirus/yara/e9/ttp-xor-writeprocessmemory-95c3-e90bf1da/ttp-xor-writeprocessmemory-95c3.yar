rule TTP_XOR_WriteProcessMemory_95c3 {
  strings:
    $key_95c3 = { c2 b1 [2] f0 93 [2] f6 a6 [2] d8 a6 [2] e7 ba }

  condition:
    any of them
}