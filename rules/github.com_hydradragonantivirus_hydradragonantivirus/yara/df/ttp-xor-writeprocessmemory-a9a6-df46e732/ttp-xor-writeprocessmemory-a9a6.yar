rule TTP_XOR_WriteProcessMemory_a9a6 {
  strings:
    $key_a9a6 = { fe d4 [2] cc f6 [2] ca c3 [2] e4 c3 [2] db df }

  condition:
    any of them
}