rule TTP_XOR_WriteProcessMemory_596b {
  strings:
    $key_596b = { 0e 19 [2] 3c 3b [2] 3a 0e [2] 14 0e [2] 2b 12 }

  condition:
    any of them
}