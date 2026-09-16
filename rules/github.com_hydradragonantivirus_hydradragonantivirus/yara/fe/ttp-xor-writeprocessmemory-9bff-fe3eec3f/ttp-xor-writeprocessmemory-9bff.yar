rule TTP_XOR_WriteProcessMemory_9bff {
  strings:
    $key_9bff = { cc 8d [2] fe af [2] f8 9a [2] d6 9a [2] e9 86 }

  condition:
    any of them
}