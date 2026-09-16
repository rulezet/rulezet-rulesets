rule TTP_XOR_WriteProcessMemory_8d0f {
  strings:
    $key_8d0f = { da 7d [2] e8 5f [2] ee 6a [2] c0 6a [2] ff 76 }

  condition:
    any of them
}