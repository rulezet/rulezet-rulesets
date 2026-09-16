rule TTP_XOR_WriteProcessMemory_123b {
  strings:
    $key_123b = { 45 49 [2] 77 6b [2] 71 5e [2] 5f 5e [2] 60 42 }

  condition:
    any of them
}