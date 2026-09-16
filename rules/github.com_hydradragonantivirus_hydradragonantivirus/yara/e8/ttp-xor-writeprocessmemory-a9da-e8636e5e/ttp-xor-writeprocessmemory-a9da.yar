rule TTP_XOR_WriteProcessMemory_a9da {
  strings:
    $key_a9da = { fe a8 [2] cc 8a [2] ca bf [2] e4 bf [2] db a3 }

  condition:
    any of them
}