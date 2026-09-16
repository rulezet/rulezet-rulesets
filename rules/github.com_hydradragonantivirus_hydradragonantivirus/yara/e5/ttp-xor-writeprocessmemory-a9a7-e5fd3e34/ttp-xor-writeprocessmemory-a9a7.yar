rule TTP_XOR_WriteProcessMemory_a9a7 {
  strings:
    $key_a9a7 = { fe d5 [2] cc f7 [2] ca c2 [2] e4 c2 [2] db de }

  condition:
    any of them
}