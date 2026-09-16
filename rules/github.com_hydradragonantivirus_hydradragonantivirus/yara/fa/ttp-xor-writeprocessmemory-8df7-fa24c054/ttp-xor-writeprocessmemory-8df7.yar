rule TTP_XOR_WriteProcessMemory_8df7 {
  strings:
    $key_8df7 = { da 85 [2] e8 a7 [2] ee 92 [2] c0 92 [2] ff 8e }

  condition:
    any of them
}