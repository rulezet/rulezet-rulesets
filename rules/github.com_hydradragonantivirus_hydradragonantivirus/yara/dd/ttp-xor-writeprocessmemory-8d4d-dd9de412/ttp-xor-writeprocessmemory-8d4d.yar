rule TTP_XOR_WriteProcessMemory_8d4d {
  strings:
    $key_8d4d = { da 3f [2] e8 1d [2] ee 28 [2] c0 28 [2] ff 34 }

  condition:
    any of them
}