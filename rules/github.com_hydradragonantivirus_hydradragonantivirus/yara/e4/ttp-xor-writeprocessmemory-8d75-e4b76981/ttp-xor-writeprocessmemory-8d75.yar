rule TTP_XOR_WriteProcessMemory_8d75 {
  strings:
    $key_8d75 = { da 07 [2] e8 25 [2] ee 10 [2] c0 10 [2] ff 0c }

  condition:
    any of them
}