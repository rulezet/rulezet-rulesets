rule TTP_XOR_WriteProcessMemory_9318 {
  strings:
    $key_9318 = { c4 6a [2] f6 48 [2] f0 7d [2] de 7d [2] e1 61 }

  condition:
    any of them
}