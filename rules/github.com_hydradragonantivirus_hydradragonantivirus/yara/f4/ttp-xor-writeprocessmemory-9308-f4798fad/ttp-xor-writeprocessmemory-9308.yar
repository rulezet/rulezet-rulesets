rule TTP_XOR_WriteProcessMemory_9308 {
  strings:
    $key_9308 = { c4 7a [2] f6 58 [2] f0 6d [2] de 6d [2] e1 71 }

  condition:
    any of them
}