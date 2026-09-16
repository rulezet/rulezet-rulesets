rule TTP_XOR_WriteProcessMemory_8df5 {
  strings:
    $key_8df5 = { da 87 [2] e8 a5 [2] ee 90 [2] c0 90 [2] ff 8c }

  condition:
    any of them
}