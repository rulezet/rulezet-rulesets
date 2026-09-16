rule TTP_XOR_WriteProcessMemory_635b {
  strings:
    $key_635b = { 34 29 [2] 06 0b [2] 00 3e [2] 2e 3e [2] 11 22 }

  condition:
    any of them
}