rule TTP_XOR_WriteProcessMemory_755b {
  strings:
    $key_755b = { 22 29 [2] 10 0b [2] 16 3e [2] 38 3e [2] 07 22 }

  condition:
    any of them
}