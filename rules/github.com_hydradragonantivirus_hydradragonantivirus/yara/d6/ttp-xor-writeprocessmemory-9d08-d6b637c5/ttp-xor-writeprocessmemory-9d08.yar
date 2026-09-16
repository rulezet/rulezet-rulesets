rule TTP_XOR_WriteProcessMemory_9d08 {
  strings:
    $key_9d08 = { ca 7a [2] f8 58 [2] fe 6d [2] d0 6d [2] ef 71 }

  condition:
    any of them
}