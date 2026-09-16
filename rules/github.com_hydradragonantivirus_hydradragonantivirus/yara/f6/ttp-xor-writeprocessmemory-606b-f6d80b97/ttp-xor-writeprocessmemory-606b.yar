rule TTP_XOR_WriteProcessMemory_606b {
  strings:
    $key_606b = { 37 19 [2] 05 3b [2] 03 0e [2] 2d 0e [2] 12 12 }

  condition:
    any of them
}