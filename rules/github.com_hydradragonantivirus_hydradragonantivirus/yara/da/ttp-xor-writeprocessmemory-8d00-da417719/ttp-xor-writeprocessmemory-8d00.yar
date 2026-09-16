rule TTP_XOR_WriteProcessMemory_8d00 {
  strings:
    $key_8d00 = { da 72 [2] e8 50 [2] ee 65 [2] c0 65 [2] ff 79 }

  condition:
    any of them
}