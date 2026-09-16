rule TTP_XOR_WriteProcessMemory_9b3f {
  strings:
    $key_9b3f = { cc 4d [2] fe 6f [2] f8 5a [2] d6 5a [2] e9 46 }

  condition:
    any of them
}