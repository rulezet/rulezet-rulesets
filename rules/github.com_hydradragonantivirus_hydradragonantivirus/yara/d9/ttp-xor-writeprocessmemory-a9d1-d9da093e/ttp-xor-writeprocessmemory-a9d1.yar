rule TTP_XOR_WriteProcessMemory_a9d1 {
  strings:
    $key_a9d1 = { fe a3 [2] cc 81 [2] ca b4 [2] e4 b4 [2] db a8 }

  condition:
    any of them
}