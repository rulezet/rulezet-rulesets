rule TTP_XOR_WriteProcessMemory_446b {
  strings:
    $key_446b = { 13 19 [2] 21 3b [2] 27 0e [2] 09 0e [2] 36 12 }

  condition:
    any of them
}