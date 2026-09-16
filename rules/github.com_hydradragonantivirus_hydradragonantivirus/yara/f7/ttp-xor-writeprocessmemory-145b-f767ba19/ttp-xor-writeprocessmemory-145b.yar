rule TTP_XOR_WriteProcessMemory_145b {
  strings:
    $key_145b = { 43 29 [2] 71 0b [2] 77 3e [2] 59 3e [2] 66 22 }

  condition:
    any of them
}