rule TTP_XOR_WriteProcessMemory_8d6a {
  strings:
    $key_8d6a = { da 18 [2] e8 3a [2] ee 0f [2] c0 0f [2] ff 13 }

  condition:
    any of them
}