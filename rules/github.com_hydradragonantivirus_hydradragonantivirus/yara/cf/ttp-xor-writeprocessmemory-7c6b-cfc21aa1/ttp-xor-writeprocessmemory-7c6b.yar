rule TTP_XOR_WriteProcessMemory_7c6b {
  strings:
    $key_7c6b = { 2b 19 [2] 19 3b [2] 1f 0e [2] 31 0e [2] 0e 12 }

  condition:
    any of them
}