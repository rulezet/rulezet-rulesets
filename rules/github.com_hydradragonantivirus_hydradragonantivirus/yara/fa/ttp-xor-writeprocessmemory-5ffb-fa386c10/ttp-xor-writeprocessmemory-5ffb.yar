rule TTP_XOR_WriteProcessMemory_5ffb {
  strings:
    $key_5ffb = { 08 89 [2] 3a ab [2] 3c 9e [2] 12 9e [2] 2d 82 }

  condition:
    any of them
}