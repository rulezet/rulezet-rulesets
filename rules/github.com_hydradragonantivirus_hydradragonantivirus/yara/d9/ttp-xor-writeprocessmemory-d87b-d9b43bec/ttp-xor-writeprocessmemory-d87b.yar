rule TTP_XOR_WriteProcessMemory_d87b {
  strings:
    $key_d87b = { 8f 09 [2] bd 2b [2] bb 1e [2] 95 1e [2] aa 02 }

  condition:
    any of them
}