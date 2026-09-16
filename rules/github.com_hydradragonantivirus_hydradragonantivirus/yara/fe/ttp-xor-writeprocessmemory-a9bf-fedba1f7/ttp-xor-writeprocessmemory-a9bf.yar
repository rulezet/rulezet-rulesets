rule TTP_XOR_WriteProcessMemory_a9bf {
  strings:
    $key_a9bf = { fe cd [2] cc ef [2] ca da [2] e4 da [2] db c6 }

  condition:
    any of them
}