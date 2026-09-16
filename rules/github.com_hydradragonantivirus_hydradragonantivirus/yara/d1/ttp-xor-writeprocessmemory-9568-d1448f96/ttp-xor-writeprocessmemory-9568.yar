rule TTP_XOR_WriteProcessMemory_9568 {
  strings:
    $key_9568 = { c2 1a [2] f0 38 [2] f6 0d [2] d8 0d [2] e7 11 }

  condition:
    any of them
}