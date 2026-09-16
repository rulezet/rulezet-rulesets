rule TTP_XOR_WriteProcessMemory_9d5b {
  strings:
    $key_9d5b = { ca 29 [2] f8 0b [2] fe 3e [2] d0 3e [2] ef 22 }

  condition:
    any of them
}