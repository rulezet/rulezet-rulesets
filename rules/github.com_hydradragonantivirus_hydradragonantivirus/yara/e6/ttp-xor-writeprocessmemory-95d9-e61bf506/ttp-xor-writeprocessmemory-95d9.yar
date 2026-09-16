rule TTP_XOR_WriteProcessMemory_95d9 {
  strings:
    $key_95d9 = { c2 ab [2] f0 89 [2] f6 bc [2] d8 bc [2] e7 a0 }

  condition:
    any of them
}