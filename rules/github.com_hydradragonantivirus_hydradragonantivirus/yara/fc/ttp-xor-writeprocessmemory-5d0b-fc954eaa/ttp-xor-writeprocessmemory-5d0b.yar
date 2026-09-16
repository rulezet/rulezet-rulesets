rule TTP_XOR_WriteProcessMemory_5d0b {
  strings:
    $key_5d0b = { 0a 79 [2] 38 5b [2] 3e 6e [2] 10 6e [2] 2f 72 }

  condition:
    any of them
}