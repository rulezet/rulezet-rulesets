rule TTP_XOR_WriteProcessMemory_9ddf {
  strings:
    $key_9ddf = { ca ad [2] f8 8f [2] fe ba [2] d0 ba [2] ef a6 }

  condition:
    any of them
}