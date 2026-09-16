rule TTP_XOR_WriteProcessMemory_333b {
  strings:
    $key_333b = { 64 49 [2] 56 6b [2] 50 5e [2] 7e 5e [2] 41 42 }

  condition:
    any of them
}