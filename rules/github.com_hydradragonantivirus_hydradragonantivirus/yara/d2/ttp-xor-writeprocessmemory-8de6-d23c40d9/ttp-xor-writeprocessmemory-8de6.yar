rule TTP_XOR_WriteProcessMemory_8de6 {
  strings:
    $key_8de6 = { da 94 [2] e8 b6 [2] ee 83 [2] c0 83 [2] ff 9f }

  condition:
    any of them
}