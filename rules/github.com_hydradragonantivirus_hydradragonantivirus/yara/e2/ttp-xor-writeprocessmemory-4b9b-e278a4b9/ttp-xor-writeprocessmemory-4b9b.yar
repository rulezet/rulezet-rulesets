rule TTP_XOR_WriteProcessMemory_4b9b {
  strings:
    $key_4b9b = { 1c e9 [2] 2e cb [2] 28 fe [2] 06 fe [2] 39 e2 }

  condition:
    any of them
}