rule TTP_XOR_WriteProcessMemory_9b28 {
  strings:
    $key_9b28 = { cc 5a [2] fe 78 [2] f8 4d [2] d6 4d [2] e9 51 }

  condition:
    any of them
}