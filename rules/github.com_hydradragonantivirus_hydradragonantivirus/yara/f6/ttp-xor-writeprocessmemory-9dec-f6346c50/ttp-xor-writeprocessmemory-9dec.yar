rule TTP_XOR_WriteProcessMemory_9dec {
  strings:
    $key_9dec = { ca 9e [2] f8 bc [2] fe 89 [2] d0 89 [2] ef 95 }

  condition:
    any of them
}