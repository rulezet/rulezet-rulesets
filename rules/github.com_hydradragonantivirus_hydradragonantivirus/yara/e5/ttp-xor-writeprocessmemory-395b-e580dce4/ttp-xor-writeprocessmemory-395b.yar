rule TTP_XOR_WriteProcessMemory_395b {
  strings:
    $key_395b = { 6e 29 [2] 5c 0b [2] 5a 3e [2] 74 3e [2] 4b 22 }

  condition:
    any of them
}