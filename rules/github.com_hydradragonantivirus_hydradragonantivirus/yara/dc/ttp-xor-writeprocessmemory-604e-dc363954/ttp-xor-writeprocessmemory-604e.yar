rule TTP_XOR_WriteProcessMemory_604e {
  strings:
    $key_604e = { 37 3c [2] 05 1e [2] 03 2b [2] 2d 2b [2] 12 37 }

  condition:
    any of them
}