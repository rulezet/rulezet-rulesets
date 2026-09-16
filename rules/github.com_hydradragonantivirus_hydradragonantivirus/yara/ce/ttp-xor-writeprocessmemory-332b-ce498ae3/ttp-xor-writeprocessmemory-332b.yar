rule TTP_XOR_WriteProcessMemory_332b {
  strings:
    $key_332b = { 64 59 [2] 56 7b [2] 50 4e [2] 7e 4e [2] 41 52 }

  condition:
    any of them
}