rule TTP_XOR_WriteProcessMemory_8d59 {
  strings:
    $key_8d59 = { da 2b [2] e8 09 [2] ee 3c [2] c0 3c [2] ff 20 }

  condition:
    any of them
}