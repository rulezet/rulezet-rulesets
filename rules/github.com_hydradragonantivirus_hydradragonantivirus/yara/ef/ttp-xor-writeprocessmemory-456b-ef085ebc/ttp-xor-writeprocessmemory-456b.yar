rule TTP_XOR_WriteProcessMemory_456b {
  strings:
    $key_456b = { 12 19 [2] 20 3b [2] 26 0e [2] 08 0e [2] 37 12 }

  condition:
    any of them
}