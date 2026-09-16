rule TTP_XOR_WriteProcessMemory_1f6b {
  strings:
    $key_1f6b = { 48 19 [2] 7a 3b [2] 7c 0e [2] 52 0e [2] 6d 12 }

  condition:
    any of them
}