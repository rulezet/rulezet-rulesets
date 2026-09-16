rule TTP_XOR_WriteProcessMemory_465b {
  strings:
    $key_465b = { 11 29 [2] 23 0b [2] 25 3e [2] 0b 3e [2] 34 22 }

  condition:
    any of them
}