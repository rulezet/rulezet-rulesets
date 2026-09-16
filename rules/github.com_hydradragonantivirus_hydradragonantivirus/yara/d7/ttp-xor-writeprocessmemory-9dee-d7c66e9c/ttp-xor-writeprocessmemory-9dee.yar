rule TTP_XOR_WriteProcessMemory_9dee {
  strings:
    $key_9dee = { ca 9c [2] f8 be [2] fe 8b [2] d0 8b [2] ef 97 }

  condition:
    any of them
}