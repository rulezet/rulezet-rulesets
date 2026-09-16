rule TTP_XOR_WriteProcessMemory_9d6f {
  strings:
    $key_9d6f = { ca 1d [2] f8 3f [2] fe 0a [2] d0 0a [2] ef 16 }

  condition:
    any of them
}