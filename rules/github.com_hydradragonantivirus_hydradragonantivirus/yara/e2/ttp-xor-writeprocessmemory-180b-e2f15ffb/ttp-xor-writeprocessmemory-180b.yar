rule TTP_XOR_WriteProcessMemory_180b {
  strings:
    $key_180b = { 4f 79 [2] 7d 5b [2] 7b 6e [2] 55 6e [2] 6a 72 }

  condition:
    any of them
}