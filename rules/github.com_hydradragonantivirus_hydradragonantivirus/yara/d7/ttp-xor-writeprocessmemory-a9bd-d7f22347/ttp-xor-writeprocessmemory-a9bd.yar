rule TTP_XOR_WriteProcessMemory_a9bd {
  strings:
    $key_a9bd = { fe cf [2] cc ed [2] ca d8 [2] e4 d8 [2] db c4 }

  condition:
    any of them
}