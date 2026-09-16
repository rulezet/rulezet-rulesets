rule TTP_XOR_WriteProcessMemory_9d39 {
  strings:
    $key_9d39 = { ca 4b [2] f8 69 [2] fe 5c [2] d0 5c [2] ef 40 }

  condition:
    any of them
}