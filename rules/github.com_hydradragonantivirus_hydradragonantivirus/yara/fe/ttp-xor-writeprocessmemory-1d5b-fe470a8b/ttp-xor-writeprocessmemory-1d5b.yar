rule TTP_XOR_WriteProcessMemory_1d5b {
  strings:
    $key_1d5b = { 4a 29 [2] 78 0b [2] 7e 3e [2] 50 3e [2] 6f 22 }

  condition:
    any of them
}