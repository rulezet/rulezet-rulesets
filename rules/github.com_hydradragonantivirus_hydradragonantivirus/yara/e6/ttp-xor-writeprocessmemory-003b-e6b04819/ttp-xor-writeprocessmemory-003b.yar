rule TTP_XOR_WriteProcessMemory_003b {
  strings:
    $key_003b = { 57 49 [2] 65 6b [2] 63 5e [2] 4d 5e [2] 72 42 }

  condition:
    any of them
}