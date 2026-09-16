rule TTP_XOR_WriteProcessMemory_5c5b {
  strings:
    $key_5c5b = { 0b 29 [2] 39 0b [2] 3f 3e [2] 11 3e [2] 2e 22 }

  condition:
    any of them
}