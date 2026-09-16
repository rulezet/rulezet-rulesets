rule TTP_XOR_WriteProcessMemory_8de5 {
  strings:
    $key_8de5 = { da 97 [2] e8 b5 [2] ee 80 [2] c0 80 [2] ff 9c }

  condition:
    any of them
}