rule TTP_XOR_WriteProcessMemory_7d2b {
  strings:
    $key_7d2b = { 2a 59 [2] 18 7b [2] 1e 4e [2] 30 4e [2] 0f 52 }

  condition:
    any of them
}