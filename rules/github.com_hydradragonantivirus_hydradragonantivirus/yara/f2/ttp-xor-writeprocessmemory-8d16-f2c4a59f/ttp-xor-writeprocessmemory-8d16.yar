rule TTP_XOR_WriteProcessMemory_8d16 {
  strings:
    $key_8d16 = { da 64 [2] e8 46 [2] ee 73 [2] c0 73 [2] ff 6f }

  condition:
    any of them
}