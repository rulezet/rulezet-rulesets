rule TTP_XOR_WriteProcessMemory_9dc1 {
  strings:
    $key_9dc1 = { ca b3 [2] f8 91 [2] fe a4 [2] d0 a4 [2] ef b8 }

  condition:
    any of them
}