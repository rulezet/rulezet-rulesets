rule TTP_XOR_WriteProcessMemory_472b {
  strings:
    $key_472b = { 10 59 [2] 22 7b [2] 24 4e [2] 0a 4e [2] 35 52 }

  condition:
    any of them
}