rule TTP_XOR_WriteProcessMemory_a9dc {
  strings:
    $key_a9dc = { fe ae [2] cc 8c [2] ca b9 [2] e4 b9 [2] db a5 }

  condition:
    any of them
}