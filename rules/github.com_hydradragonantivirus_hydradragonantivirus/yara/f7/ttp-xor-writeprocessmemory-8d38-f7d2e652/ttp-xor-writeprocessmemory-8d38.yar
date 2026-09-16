rule TTP_XOR_WriteProcessMemory_8d38 {
  strings:
    $key_8d38 = { da 4a [2] e8 68 [2] ee 5d [2] c0 5d [2] ff 41 }

  condition:
    any of them
}