rule TTP_XOR_WriteProcessMemory_8d2e {
  strings:
    $key_8d2e = { da 5c [2] e8 7e [2] ee 4b [2] c0 4b [2] ff 57 }

  condition:
    any of them
}