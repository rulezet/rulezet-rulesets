rule TTP_XOR_WriteProcessMemory_8d47 {
  strings:
    $key_8d47 = { da 35 [2] e8 17 [2] ee 22 [2] c0 22 [2] ff 3e }

  condition:
    any of them
}