rule TTP_XOR_WriteProcessMemory_3e0b {
  strings:
    $key_3e0b = { 69 79 [2] 5b 5b [2] 5d 6e [2] 73 6e [2] 4c 72 }

  condition:
    any of them
}