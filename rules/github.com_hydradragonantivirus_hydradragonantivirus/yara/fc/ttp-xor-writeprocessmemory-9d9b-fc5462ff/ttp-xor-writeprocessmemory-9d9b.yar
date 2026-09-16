rule TTP_XOR_WriteProcessMemory_9d9b {
  strings:
    $key_9d9b = { ca e9 [2] f8 cb [2] fe fe [2] d0 fe [2] ef e2 }

  condition:
    any of them
}