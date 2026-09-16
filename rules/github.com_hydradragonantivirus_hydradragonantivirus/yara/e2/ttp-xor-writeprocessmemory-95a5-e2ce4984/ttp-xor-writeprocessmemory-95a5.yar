rule TTP_XOR_WriteProcessMemory_95a5 {
  strings:
    $key_95a5 = { c2 d7 [2] f0 f5 [2] f6 c0 [2] d8 c0 [2] e7 dc }

  condition:
    any of them
}