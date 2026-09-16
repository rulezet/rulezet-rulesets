rule TTP_XOR_WriteProcessMemory_223b {
  strings:
    $key_223b = { 75 49 [2] 47 6b [2] 41 5e [2] 6f 5e [2] 50 42 }

  condition:
    any of them
}