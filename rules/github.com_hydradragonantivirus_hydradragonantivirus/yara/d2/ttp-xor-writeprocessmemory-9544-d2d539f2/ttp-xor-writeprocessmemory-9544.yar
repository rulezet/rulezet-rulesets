rule TTP_XOR_WriteProcessMemory_9544 {
  strings:
    $key_9544 = { c2 36 [2] f0 14 [2] f6 21 [2] d8 21 [2] e7 3d }

  condition:
    any of them
}