rule TTP_XOR_WriteProcessMemory_9b58 {
  strings:
    $key_9b58 = { cc 2a [2] fe 08 [2] f8 3d [2] d6 3d [2] e9 21 }

  condition:
    any of them
}