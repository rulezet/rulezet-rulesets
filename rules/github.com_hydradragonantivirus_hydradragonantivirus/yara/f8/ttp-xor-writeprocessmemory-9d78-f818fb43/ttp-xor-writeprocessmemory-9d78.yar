rule TTP_XOR_WriteProcessMemory_9d78 {
  strings:
    $key_9d78 = { ca 0a [2] f8 28 [2] fe 1d [2] d0 1d [2] ef 01 }

  condition:
    any of them
}