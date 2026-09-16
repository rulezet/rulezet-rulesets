rule TTP_XOR_WriteProcessMemory_6ffb {
  strings:
    $key_6ffb = { 38 89 [2] 0a ab [2] 0c 9e [2] 22 9e [2] 1d 82 }

  condition:
    any of them
}