rule TTP_XOR_WriteProcessMemory_795b {
  strings:
    $key_795b = { 2e 29 [2] 1c 0b [2] 1a 3e [2] 34 3e [2] 0b 22 }

  condition:
    any of them
}