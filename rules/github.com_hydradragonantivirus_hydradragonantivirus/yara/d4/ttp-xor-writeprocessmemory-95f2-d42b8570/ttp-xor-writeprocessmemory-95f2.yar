rule TTP_XOR_WriteProcessMemory_95f2 {
  strings:
    $key_95f2 = { c2 80 [2] f0 a2 [2] f6 97 [2] d8 97 [2] e7 8b }

  condition:
    any of them
}