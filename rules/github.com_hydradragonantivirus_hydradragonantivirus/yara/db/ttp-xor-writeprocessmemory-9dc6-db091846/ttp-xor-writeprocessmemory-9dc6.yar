rule TTP_XOR_WriteProcessMemory_9dc6 {
  strings:
    $key_9dc6 = { ca b4 [2] f8 96 [2] fe a3 [2] d0 a3 [2] ef bf }

  condition:
    any of them
}