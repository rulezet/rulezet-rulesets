rule TTP_XOR_WriteProcessMemory_6c0b {
  strings:
    $key_6c0b = { 3b 79 [2] 09 5b [2] 0f 6e [2] 21 6e [2] 1e 72 }

  condition:
    any of them
}