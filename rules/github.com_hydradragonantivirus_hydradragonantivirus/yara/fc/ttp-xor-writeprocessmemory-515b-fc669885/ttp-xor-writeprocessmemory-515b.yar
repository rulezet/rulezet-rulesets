rule TTP_XOR_WriteProcessMemory_515b {
  strings:
    $key_515b = { 06 29 [2] 34 0b [2] 32 3e [2] 1c 3e [2] 23 22 }

  condition:
    any of them
}