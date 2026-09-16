rule TTP_XOR_WriteProcessMemory_9d4f {
  strings:
    $key_9d4f = { ca 3d [2] f8 1f [2] fe 2a [2] d0 2a [2] ef 36 }

  condition:
    any of them
}