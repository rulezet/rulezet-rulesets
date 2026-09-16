rule TTP_XOR_WriteProcessMemory_9d5f {
  strings:
    $key_9d5f = { ca 2d [2] f8 0f [2] fe 3a [2] d0 3a [2] ef 26 }

  condition:
    any of them
}