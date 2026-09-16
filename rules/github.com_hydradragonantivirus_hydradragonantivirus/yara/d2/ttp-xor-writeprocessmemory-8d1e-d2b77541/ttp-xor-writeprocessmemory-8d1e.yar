rule TTP_XOR_WriteProcessMemory_8d1e {
  strings:
    $key_8d1e = { da 6c [2] e8 4e [2] ee 7b [2] c0 7b [2] ff 67 }

  condition:
    any of them
}