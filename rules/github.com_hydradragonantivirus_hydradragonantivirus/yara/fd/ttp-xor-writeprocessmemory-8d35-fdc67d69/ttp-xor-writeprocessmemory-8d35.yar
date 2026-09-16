rule TTP_XOR_WriteProcessMemory_8d35 {
  strings:
    $key_8d35 = { da 47 [2] e8 65 [2] ee 50 [2] c0 50 [2] ff 4c }

  condition:
    any of them
}