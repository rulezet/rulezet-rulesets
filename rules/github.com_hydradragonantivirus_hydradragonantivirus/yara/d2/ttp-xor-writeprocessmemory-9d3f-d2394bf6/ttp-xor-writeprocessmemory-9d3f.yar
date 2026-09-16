rule TTP_XOR_WriteProcessMemory_9d3f {
  strings:
    $key_9d3f = { ca 4d [2] f8 6f [2] fe 5a [2] d0 5a [2] ef 46 }

  condition:
    any of them
}