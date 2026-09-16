rule TTP_XOR_WriteProcessMemory_d80e {
  strings:
    $key_d80e = { 8f 7c [2] bd 5e [2] bb 6b [2] 95 6b [2] aa 77 }

  condition:
    any of them
}