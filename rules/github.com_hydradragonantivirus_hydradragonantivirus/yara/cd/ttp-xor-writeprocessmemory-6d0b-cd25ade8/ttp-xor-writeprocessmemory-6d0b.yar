rule TTP_XOR_WriteProcessMemory_6d0b {
  strings:
    $key_6d0b = { 3a 79 [2] 08 5b [2] 0e 6e [2] 20 6e [2] 1f 72 }

  condition:
    any of them
}