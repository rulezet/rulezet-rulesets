rule TTP_XOR_WriteProcessMemory_cf1c {
  strings:
    $key_cf1c = { 98 6e [2] aa 4c [2] ac 79 [2] 82 79 [2] bd 65 }

  condition:
    any of them
}