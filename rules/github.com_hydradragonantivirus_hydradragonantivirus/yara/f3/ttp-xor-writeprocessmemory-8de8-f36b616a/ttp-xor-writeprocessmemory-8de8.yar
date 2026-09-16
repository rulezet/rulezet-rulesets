rule TTP_XOR_WriteProcessMemory_8de8 {
  strings:
    $key_8de8 = { da 9a [2] e8 b8 [2] ee 8d [2] c0 8d [2] ff 91 }

  condition:
    any of them
}