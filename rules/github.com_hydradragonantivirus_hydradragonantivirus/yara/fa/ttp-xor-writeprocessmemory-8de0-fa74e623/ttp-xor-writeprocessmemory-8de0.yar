rule TTP_XOR_WriteProcessMemory_8de0 {
  strings:
    $key_8de0 = { da 92 [2] e8 b0 [2] ee 85 [2] c0 85 [2] ff 99 }

  condition:
    any of them
}