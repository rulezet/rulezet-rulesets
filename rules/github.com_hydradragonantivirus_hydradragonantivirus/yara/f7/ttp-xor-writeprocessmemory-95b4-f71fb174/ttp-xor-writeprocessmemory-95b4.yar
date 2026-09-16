rule TTP_XOR_WriteProcessMemory_95b4 {
  strings:
    $key_95b4 = { c2 c6 [2] f0 e4 [2] f6 d1 [2] d8 d1 [2] e7 cd }

  condition:
    any of them
}