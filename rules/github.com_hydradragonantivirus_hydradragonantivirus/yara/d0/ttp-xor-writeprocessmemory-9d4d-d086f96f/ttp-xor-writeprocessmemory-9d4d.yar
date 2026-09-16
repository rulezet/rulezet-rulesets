rule TTP_XOR_WriteProcessMemory_9d4d {
  strings:
    $key_9d4d = { ca 3f [2] f8 1d [2] fe 28 [2] d0 28 [2] ef 34 }

  condition:
    any of them
}