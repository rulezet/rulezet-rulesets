rule TTP_XOR_WriteProcessMemory_a9a1 {
  strings:
    $key_a9a1 = { fe d3 [2] cc f1 [2] ca c4 [2] e4 c4 [2] db d8 }

  condition:
    any of them
}