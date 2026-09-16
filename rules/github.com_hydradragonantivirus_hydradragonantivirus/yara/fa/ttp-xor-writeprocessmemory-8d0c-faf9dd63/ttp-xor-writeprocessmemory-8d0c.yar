rule TTP_XOR_WriteProcessMemory_8d0c {
  strings:
    $key_8d0c = { da 7e [2] e8 5c [2] ee 69 [2] c0 69 [2] ff 75 }

  condition:
    any of them
}