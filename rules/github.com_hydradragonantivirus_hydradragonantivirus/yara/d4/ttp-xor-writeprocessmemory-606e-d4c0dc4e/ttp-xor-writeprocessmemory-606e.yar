rule TTP_XOR_WriteProcessMemory_606e {
  strings:
    $key_606e = { 37 1c [2] 05 3e [2] 03 0b [2] 2d 0b [2] 12 17 }

  condition:
    any of them
}