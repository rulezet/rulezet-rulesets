rule TTP_XOR_WriteProcessMemory_9d3b {
  strings:
    $key_9d3b = { ca 49 [2] f8 6b [2] fe 5e [2] d0 5e [2] ef 42 }

  condition:
    any of them
}