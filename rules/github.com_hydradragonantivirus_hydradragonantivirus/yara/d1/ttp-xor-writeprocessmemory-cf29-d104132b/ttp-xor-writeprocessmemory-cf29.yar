rule TTP_XOR_WriteProcessMemory_cf29 {
  strings:
    $key_cf29 = { 98 5b [2] aa 79 [2] ac 4c [2] 82 4c [2] bd 50 }

  condition:
    any of them
}