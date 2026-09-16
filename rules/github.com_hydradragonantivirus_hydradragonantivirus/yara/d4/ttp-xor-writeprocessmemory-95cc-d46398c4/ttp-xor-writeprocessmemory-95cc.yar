rule TTP_XOR_WriteProcessMemory_95cc {
  strings:
    $key_95cc = { c2 be [2] f0 9c [2] f6 a9 [2] d8 a9 [2] e7 b5 }

  condition:
    any of them
}