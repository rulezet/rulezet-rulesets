rule TTP_XOR_WriteProcessMemory_2f0b {
  strings:
    $key_2f0b = { 78 79 [2] 4a 5b [2] 4c 6e [2] 62 6e [2] 5d 72 }

  condition:
    any of them
}