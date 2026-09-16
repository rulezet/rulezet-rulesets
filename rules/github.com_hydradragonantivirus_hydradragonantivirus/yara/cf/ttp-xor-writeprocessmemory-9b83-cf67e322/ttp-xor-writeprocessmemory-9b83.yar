rule TTP_XOR_WriteProcessMemory_9b83 {
  strings:
    $key_9b83 = { cc f1 [2] fe d3 [2] f8 e6 [2] d6 e6 [2] e9 fa }

  condition:
    any of them
}