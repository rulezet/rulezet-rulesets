rule TTP_XOR_WriteProcessMemory_9d89 {
  strings:
    $key_9d89 = { ca fb [2] f8 d9 [2] fe ec [2] d0 ec [2] ef f0 }

  condition:
    any of them
}