rule TTP_XOR_WriteProcessMemory_2d5b {
  strings:
    $key_2d5b = { 7a 29 [2] 48 0b [2] 4e 3e [2] 60 3e [2] 5f 22 }

  condition:
    any of them
}