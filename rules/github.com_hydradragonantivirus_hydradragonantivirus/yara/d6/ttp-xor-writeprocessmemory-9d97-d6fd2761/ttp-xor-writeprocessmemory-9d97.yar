rule TTP_XOR_WriteProcessMemory_9d97 {
  strings:
    $key_9d97 = { ca e5 [2] f8 c7 [2] fe f2 [2] d0 f2 [2] ef ee }

  condition:
    any of them
}