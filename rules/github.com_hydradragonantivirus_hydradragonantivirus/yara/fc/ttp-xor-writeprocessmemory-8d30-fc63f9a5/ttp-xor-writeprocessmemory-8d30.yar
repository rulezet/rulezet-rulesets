rule TTP_XOR_WriteProcessMemory_8d30 {
  strings:
    $key_8d30 = { da 42 [2] e8 60 [2] ee 55 [2] c0 55 [2] ff 49 }

  condition:
    any of them
}