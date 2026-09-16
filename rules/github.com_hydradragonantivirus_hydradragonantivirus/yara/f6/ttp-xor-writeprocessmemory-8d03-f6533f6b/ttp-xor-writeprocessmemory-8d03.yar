rule TTP_XOR_WriteProcessMemory_8d03 {
  strings:
    $key_8d03 = { da 71 [2] e8 53 [2] ee 66 [2] c0 66 [2] ff 7a }

  condition:
    any of them
}