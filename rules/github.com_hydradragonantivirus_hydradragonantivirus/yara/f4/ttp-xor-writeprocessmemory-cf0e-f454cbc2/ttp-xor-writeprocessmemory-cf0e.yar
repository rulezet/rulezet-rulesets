rule TTP_XOR_WriteProcessMemory_cf0e {
  strings:
    $key_cf0e = { 98 7c [2] aa 5e [2] ac 6b [2] 82 6b [2] bd 77 }

  condition:
    any of them
}