rule TTP_XOR_WriteProcessMemory_783b {
  strings:
    $key_783b = { 2f 49 [2] 1d 6b [2] 1b 5e [2] 35 5e [2] 0a 42 }

  condition:
    any of them
}