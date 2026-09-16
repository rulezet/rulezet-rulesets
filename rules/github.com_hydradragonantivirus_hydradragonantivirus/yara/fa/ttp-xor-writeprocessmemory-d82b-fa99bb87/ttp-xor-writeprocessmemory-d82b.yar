rule TTP_XOR_WriteProcessMemory_d82b {
  strings:
    $key_d82b = { 8f 59 [2] bd 7b [2] bb 4e [2] 95 4e [2] aa 52 }

  condition:
    any of them
}