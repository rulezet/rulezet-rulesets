rule TTP_XOR_WriteProcessMemory_8d08 {
  strings:
    $key_8d08 = { da 7a [2] e8 58 [2] ee 6d [2] c0 6d [2] ff 71 }

  condition:
    any of them
}