rule TTP_XOR_WriteProcessMemory_cf3b {
  strings:
    $key_cf3b = { 98 49 [2] aa 6b [2] ac 5e [2] 82 5e [2] bd 42 }

  condition:
    any of them
}