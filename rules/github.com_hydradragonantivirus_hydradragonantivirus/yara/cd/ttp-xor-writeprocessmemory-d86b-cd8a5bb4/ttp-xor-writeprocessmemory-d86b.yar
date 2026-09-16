rule TTP_XOR_WriteProcessMemory_d86b {
  strings:
    $key_d86b = { 8f 19 [2] bd 3b [2] bb 0e [2] 95 0e [2] aa 12 }

  condition:
    any of them
}