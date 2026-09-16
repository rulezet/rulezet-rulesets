rule TTP_XOR_WriteProcessMemory_8d6c {
  strings:
    $key_8d6c = { da 1e [2] e8 3c [2] ee 09 [2] c0 09 [2] ff 15 }

  condition:
    any of them
}