rule TTP_XOR_WriteProcessMemory_036b {
  strings:
    $key_036b = { 54 19 [2] 66 3b [2] 60 0e [2] 4e 0e [2] 71 12 }

  condition:
    any of them
}