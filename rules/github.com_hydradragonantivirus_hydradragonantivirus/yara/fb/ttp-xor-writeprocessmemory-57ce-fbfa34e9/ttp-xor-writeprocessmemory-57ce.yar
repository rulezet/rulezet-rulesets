rule TTP_XOR_WriteProcessMemory_57ce {
  strings:
    $key_57ce = { 00 bc [2] 32 9e [2] 34 ab [2] 1a ab [2] 25 b7 }

  condition:
    any of them
}