rule TTP_XOR_WriteProcessMemory_505b {
  strings:
    $key_505b = { 07 29 [2] 35 0b [2] 33 3e [2] 1d 3e [2] 22 22 }

  condition:
    any of them
}