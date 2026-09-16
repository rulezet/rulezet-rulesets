rule TTP_XOR_WriteProcessMemory_9d92 {
  strings:
    $key_9d92 = { ca e0 [2] f8 c2 [2] fe f7 [2] d0 f7 [2] ef eb }

  condition:
    any of them
}