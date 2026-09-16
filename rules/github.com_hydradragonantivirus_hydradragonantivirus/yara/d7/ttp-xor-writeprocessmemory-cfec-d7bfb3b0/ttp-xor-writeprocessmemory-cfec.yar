rule TTP_XOR_WriteProcessMemory_cfec {
  strings:
    $key_cfec = { 98 9e [2] aa bc [2] ac 89 [2] 82 89 [2] bd 95 }

  condition:
    any of them
}