rule TTP_XOR_WriteProcessMemory_9538 {
  strings:
    $key_9538 = { c2 4a [2] f0 68 [2] f6 5d [2] d8 5d [2] e7 41 }

  condition:
    any of them
}