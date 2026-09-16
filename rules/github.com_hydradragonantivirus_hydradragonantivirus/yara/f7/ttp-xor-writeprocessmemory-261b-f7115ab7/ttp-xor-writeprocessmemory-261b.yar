rule TTP_XOR_WriteProcessMemory_261b {
  strings:
    $key_261b = { 71 69 [2] 43 4b [2] 45 7e [2] 6b 7e [2] 54 62 }

  condition:
    any of them
}