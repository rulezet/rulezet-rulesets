rule TTP_XOR_WriteProcessMemory_072b {
  strings:
    $key_072b = { 50 59 [2] 62 7b [2] 64 4e [2] 4a 4e [2] 75 52 }

  condition:
    any of them
}