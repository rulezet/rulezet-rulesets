rule TTP_XOR_WriteProcessMemory_9d5e {
  strings:
    $key_9d5e = { ca 2c [2] f8 0e [2] fe 3b [2] d0 3b [2] ef 27 }

  condition:
    any of them
}