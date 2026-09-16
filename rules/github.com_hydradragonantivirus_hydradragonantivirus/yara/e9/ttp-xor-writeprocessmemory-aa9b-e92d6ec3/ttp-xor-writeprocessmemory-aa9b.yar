rule TTP_XOR_WriteProcessMemory_aa9b {
  strings:
    $key_aa9b = { fd e9 [2] cf cb [2] c9 fe [2] e7 fe [2] d8 e2 }

  condition:
    any of them
}