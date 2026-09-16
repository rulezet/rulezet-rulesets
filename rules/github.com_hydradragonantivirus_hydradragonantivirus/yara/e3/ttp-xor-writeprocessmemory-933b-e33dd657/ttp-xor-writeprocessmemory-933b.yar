rule TTP_XOR_WriteProcessMemory_933b {
  strings:
    $key_933b = { c4 49 [2] f6 6b [2] f0 5e [2] de 5e [2] e1 42 }

  condition:
    any of them
}