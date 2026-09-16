rule TTP_XOR_WriteProcessMemory_402b {
  strings:
    $key_402b = { 17 59 [2] 25 7b [2] 23 4e [2] 0d 4e [2] 32 52 }

  condition:
    any of them
}