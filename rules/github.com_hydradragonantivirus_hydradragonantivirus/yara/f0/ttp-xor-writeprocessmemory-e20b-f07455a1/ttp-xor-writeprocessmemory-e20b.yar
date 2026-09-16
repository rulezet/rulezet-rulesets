rule TTP_XOR_WriteProcessMemory_e20b {
  strings:
    $key_e20b = { b5 79 [2] 87 5b [2] 81 6e [2] af 6e [2] 90 72 }

  condition:
    any of them
}