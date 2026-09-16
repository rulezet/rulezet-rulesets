rule TTP_XOR_WriteProcessMemory_440b {
  strings:
    $key_440b = { 13 79 [2] 21 5b [2] 27 6e [2] 09 6e [2] 36 72 }

  condition:
    any of them
}