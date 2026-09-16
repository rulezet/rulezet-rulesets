rule TTP_XOR_WriteProcessMemory_9591 {
  strings:
    $key_9591 = { c2 e3 [2] f0 c1 [2] f6 f4 [2] d8 f4 [2] e7 e8 }

  condition:
    any of them
}