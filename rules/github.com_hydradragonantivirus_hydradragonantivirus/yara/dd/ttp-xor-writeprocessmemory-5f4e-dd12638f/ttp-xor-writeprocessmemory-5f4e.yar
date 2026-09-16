rule TTP_XOR_WriteProcessMemory_5f4e {
  strings:
    $key_5f4e = { 08 3c [2] 3a 1e [2] 3c 2b [2] 12 2b [2] 2d 37 }

  condition:
    any of them
}