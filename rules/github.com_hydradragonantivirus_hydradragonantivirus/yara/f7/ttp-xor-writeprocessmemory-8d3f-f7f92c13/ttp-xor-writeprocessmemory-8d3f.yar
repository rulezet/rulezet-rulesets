rule TTP_XOR_WriteProcessMemory_8d3f {
  strings:
    $key_8d3f = { da 4d [2] e8 6f [2] ee 5a [2] c0 5a [2] ff 46 }

  condition:
    any of them
}