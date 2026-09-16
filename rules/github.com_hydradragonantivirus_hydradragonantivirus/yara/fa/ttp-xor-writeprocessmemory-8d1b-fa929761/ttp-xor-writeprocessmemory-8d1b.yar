rule TTP_XOR_WriteProcessMemory_8d1b {
  strings:
    $key_8d1b = { da 69 [2] e8 4b [2] ee 7e [2] c0 7e [2] ff 62 }

  condition:
    any of them
}