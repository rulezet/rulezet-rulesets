rule TTP_XOR_WriteProcessMemory_8d33 {
  strings:
    $key_8d33 = { da 41 [2] e8 63 [2] ee 56 [2] c0 56 [2] ff 4a }

  condition:
    any of them
}