rule TTP_XOR_WriteProcessMemory_8d06 {
  strings:
    $key_8d06 = { da 74 [2] e8 56 [2] ee 63 [2] c0 63 [2] ff 7f }

  condition:
    any of them
}