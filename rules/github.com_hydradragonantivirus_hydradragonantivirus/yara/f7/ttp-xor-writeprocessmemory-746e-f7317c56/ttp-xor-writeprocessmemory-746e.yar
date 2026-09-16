rule TTP_XOR_WriteProcessMemory_746e {
  strings:
    $key_746e = { 23 1c [2] 11 3e [2] 17 0b [2] 39 0b [2] 06 17 }

  condition:
    any of them
}