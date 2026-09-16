rule TTP_XOR_WriteProcessMemory_236b {
  strings:
    $key_236b = { 74 19 [2] 46 3b [2] 40 0e [2] 6e 0e [2] 51 12 }

  condition:
    any of them
}