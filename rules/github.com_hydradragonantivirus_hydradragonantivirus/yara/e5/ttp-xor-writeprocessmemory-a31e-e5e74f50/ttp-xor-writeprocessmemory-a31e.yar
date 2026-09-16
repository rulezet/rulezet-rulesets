rule TTP_XOR_WriteProcessMemory_a31e {
  strings:
    $key_a31e = { f4 6c [2] c6 4e [2] c0 7b [2] ee 7b [2] d1 67 }

  condition:
    any of them
}