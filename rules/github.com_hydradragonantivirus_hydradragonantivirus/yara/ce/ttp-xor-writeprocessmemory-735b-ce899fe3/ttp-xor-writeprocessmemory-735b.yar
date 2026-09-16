rule TTP_XOR_WriteProcessMemory_735b {
  strings:
    $key_735b = { 24 29 [2] 16 0b [2] 10 3e [2] 3e 3e [2] 01 22 }

  condition:
    any of them
}