rule TTP_XOR_WriteProcessMemory_a32a {
  strings:
    $key_a32a = { f4 58 [2] c6 7a [2] c0 4f [2] ee 4f [2] d1 53 }

  condition:
    any of them
}