rule TTP_XOR_WriteProcessMemory_9577 {
  strings:
    $key_9577 = { c2 05 [2] f0 27 [2] f6 12 [2] d8 12 [2] e7 0e }

  condition:
    any of them
}