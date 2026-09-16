rule TTP_XOR_WriteProcessMemory_9bca {
  strings:
    $key_9bca = { cc b8 [2] fe 9a [2] f8 af [2] d6 af [2] e9 b3 }

  condition:
    any of them
}