rule TTP_XOR_WriteProcessMemory_9528 {
  strings:
    $key_9528 = { c2 5a [2] f0 78 [2] f6 4d [2] d8 4d [2] e7 51 }

  condition:
    any of them
}