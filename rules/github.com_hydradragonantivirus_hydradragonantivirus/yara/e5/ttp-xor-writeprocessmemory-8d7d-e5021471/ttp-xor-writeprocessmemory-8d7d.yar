rule TTP_XOR_WriteProcessMemory_8d7d {
  strings:
    $key_8d7d = { da 0f [2] e8 2d [2] ee 18 [2] c0 18 [2] ff 04 }

  condition:
    any of them
}