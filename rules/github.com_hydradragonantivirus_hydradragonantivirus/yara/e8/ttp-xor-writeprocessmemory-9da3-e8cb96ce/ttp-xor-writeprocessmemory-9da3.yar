rule TTP_XOR_WriteProcessMemory_9da3 {
  strings:
    $key_9da3 = { ca d1 [2] f8 f3 [2] fe c6 [2] d0 c6 [2] ef da }

  condition:
    any of them
}