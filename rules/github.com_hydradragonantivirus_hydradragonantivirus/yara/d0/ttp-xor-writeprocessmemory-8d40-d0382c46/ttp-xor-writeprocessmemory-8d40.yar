rule TTP_XOR_WriteProcessMemory_8d40 {
  strings:
    $key_8d40 = { da 32 [2] e8 10 [2] ee 25 [2] c0 25 [2] ff 39 }

  condition:
    any of them
}