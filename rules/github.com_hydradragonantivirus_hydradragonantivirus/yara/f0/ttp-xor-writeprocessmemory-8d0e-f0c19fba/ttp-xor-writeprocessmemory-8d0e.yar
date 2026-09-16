rule TTP_XOR_WriteProcessMemory_8d0e {
  strings:
    $key_8d0e = { da 7c [2] e8 5e [2] ee 6b [2] c0 6b [2] ff 77 }

  condition:
    any of them
}