rule TTP_XOR_WriteProcessMemory_9d4b {
  strings:
    $key_9d4b = { ca 39 [2] f8 1b [2] fe 2e [2] d0 2e [2] ef 32 }

  condition:
    any of them
}