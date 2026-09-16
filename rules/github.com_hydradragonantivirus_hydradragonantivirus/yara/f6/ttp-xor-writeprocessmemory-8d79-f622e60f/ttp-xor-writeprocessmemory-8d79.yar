rule TTP_XOR_WriteProcessMemory_8d79 {
  strings:
    $key_8d79 = { da 0b [2] e8 29 [2] ee 1c [2] c0 1c [2] ff 00 }

  condition:
    any of them
}