rule TTP_XOR_WriteProcessMemory_643b {
  strings:
    $key_643b = { 33 49 [2] 01 6b [2] 07 5e [2] 29 5e [2] 16 42 }

  condition:
    any of them
}