rule TTP_XOR_WriteProcessMemory_9d2b {
  strings:
    $key_9d2b = { ca 59 [2] f8 7b [2] fe 4e [2] d0 4e [2] ef 52 }

  condition:
    any of them
}