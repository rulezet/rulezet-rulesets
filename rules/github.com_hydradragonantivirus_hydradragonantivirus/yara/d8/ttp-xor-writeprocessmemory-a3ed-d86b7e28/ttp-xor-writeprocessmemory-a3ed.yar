rule TTP_XOR_WriteProcessMemory_a3ed {
  strings:
    $key_a3ed = { f4 9f [2] c6 bd [2] c0 88 [2] ee 88 [2] d1 94 }

  condition:
    any of them
}