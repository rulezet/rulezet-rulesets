rule TTP_XOR_WriteProcessMemory_746c {
  strings:
    $key_746c = { 23 1e [2] 11 3c [2] 17 09 [2] 39 09 [2] 06 15 }

  condition:
    any of them
}