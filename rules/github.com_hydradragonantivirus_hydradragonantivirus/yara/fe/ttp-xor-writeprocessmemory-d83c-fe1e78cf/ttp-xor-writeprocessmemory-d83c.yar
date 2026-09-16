rule TTP_XOR_WriteProcessMemory_d83c {
  strings:
    $key_d83c = { 8f 4e [2] bd 6c [2] bb 59 [2] 95 59 [2] aa 45 }

  condition:
    any of them
}