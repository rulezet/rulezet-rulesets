rule TTP_XOR_WriteProcessMemory_006b {
  strings:
    $key_006b = { 57 19 [2] 65 3b [2] 63 0e [2] 4d 0e [2] 72 12 }

  condition:
    any of them
}