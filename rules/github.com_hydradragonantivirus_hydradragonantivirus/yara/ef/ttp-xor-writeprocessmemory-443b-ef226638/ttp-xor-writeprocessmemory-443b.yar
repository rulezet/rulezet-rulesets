rule TTP_XOR_WriteProcessMemory_443b {
  strings:
    $key_443b = { 13 49 [2] 21 6b [2] 27 5e [2] 09 5e [2] 36 42 }

  condition:
    any of them
}