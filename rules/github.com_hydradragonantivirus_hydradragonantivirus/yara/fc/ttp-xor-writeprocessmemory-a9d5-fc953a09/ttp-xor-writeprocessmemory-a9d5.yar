rule TTP_XOR_WriteProcessMemory_a9d5 {
  strings:
    $key_a9d5 = { fe a7 [2] cc 85 [2] ca b0 [2] e4 b0 [2] db ac }

  condition:
    any of them
}