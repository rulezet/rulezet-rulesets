rule TTP_XOR_WriteProcessMemory_0a0b {
  strings:
    $key_0a0b = { 5d 79 [2] 6f 5b [2] 69 6e [2] 47 6e [2] 78 72 }

  condition:
    any of them
}