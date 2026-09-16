rule TTP_XOR_WriteProcessMemory_435b {
  strings:
    $key_435b = { 14 29 [2] 26 0b [2] 20 3e [2] 0e 3e [2] 31 22 }

  condition:
    any of them
}