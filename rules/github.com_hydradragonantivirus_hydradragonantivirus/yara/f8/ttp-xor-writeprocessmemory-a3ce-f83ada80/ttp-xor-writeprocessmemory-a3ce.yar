rule TTP_XOR_WriteProcessMemory_a3ce {
  strings:
    $key_a3ce = { f4 bc [2] c6 9e [2] c0 ab [2] ee ab [2] d1 b7 }

  condition:
    any of them
}