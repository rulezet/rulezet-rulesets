rule TTP_XOR_WriteProcessMemory_9b4f {
  strings:
    $key_9b4f = { cc 3d [2] fe 1f [2] f8 2a [2] d6 2a [2] e9 36 }

  condition:
    any of them
}