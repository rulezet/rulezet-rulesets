rule TTP_XOR_WriteProcessMemory_373b {
  strings:
    $key_373b = { 60 49 [2] 52 6b [2] 54 5e [2] 7a 5e [2] 45 42 }

  condition:
    any of them
}