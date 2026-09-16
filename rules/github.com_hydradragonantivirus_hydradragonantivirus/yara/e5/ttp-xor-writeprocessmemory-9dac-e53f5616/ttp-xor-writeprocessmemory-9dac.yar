rule TTP_XOR_WriteProcessMemory_9dac {
  strings:
    $key_9dac = { ca de [2] f8 fc [2] fe c9 [2] d0 c9 [2] ef d5 }

  condition:
    any of them
}