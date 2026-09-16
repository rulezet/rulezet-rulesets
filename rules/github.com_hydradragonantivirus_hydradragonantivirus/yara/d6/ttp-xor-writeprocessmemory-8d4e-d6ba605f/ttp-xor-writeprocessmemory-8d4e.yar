rule TTP_XOR_WriteProcessMemory_8d4e {
  strings:
    $key_8d4e = { da 3c [2] e8 1e [2] ee 2b [2] c0 2b [2] ff 37 }

  condition:
    any of them
}