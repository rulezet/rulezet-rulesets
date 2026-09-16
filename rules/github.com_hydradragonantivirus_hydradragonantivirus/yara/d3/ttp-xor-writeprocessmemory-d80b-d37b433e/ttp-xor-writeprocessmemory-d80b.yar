rule TTP_XOR_WriteProcessMemory_d80b {
  strings:
    $key_d80b = { 8f 79 [2] bd 5b [2] bb 6e [2] 95 6e [2] aa 72 }

  condition:
    any of them
}