rule TTP_XOR_WriteProcessMemory_8d0b {
  strings:
    $key_8d0b = { da 79 [2] e8 5b [2] ee 6e [2] c0 6e [2] ff 72 }

  condition:
    any of them
}