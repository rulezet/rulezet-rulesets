rule TTP_XOR_WriteProcessMemory_a9d7 {
  strings:
    $key_a9d7 = { fe a5 [2] cc 87 [2] ca b2 [2] e4 b2 [2] db ae }

  condition:
    any of them
}