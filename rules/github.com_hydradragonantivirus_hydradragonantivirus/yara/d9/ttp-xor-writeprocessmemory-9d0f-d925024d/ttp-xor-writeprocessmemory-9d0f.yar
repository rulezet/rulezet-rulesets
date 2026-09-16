rule TTP_XOR_WriteProcessMemory_9d0f {
  strings:
    $key_9d0f = { ca 7d [2] f8 5f [2] fe 6a [2] d0 6a [2] ef 76 }

  condition:
    any of them
}