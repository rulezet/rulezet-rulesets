rule TTP_XOR_WriteProcessMemory_595b {
  strings:
    $key_595b = { 0e 29 [2] 3c 0b [2] 3a 3e [2] 14 3e [2] 2b 22 }

  condition:
    any of them
}