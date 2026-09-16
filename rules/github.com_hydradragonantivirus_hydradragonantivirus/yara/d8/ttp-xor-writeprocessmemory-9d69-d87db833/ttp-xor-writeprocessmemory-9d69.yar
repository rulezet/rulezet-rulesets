rule TTP_XOR_WriteProcessMemory_9d69 {
  strings:
    $key_9d69 = { ca 1b [2] f8 39 [2] fe 0c [2] d0 0c [2] ef 10 }

  condition:
    any of them
}