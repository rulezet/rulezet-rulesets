rule TTP_XOR_WriteProcessMemory_8d70 {
  strings:
    $key_8d70 = { da 02 [2] e8 20 [2] ee 15 [2] c0 15 [2] ff 09 }

  condition:
    any of them
}