rule TTP_XOR_WriteProcessMemory_9d95 {
  strings:
    $key_9d95 = { ca e7 [2] f8 c5 [2] fe f0 [2] d0 f0 [2] ef ec }

  condition:
    any of them
}