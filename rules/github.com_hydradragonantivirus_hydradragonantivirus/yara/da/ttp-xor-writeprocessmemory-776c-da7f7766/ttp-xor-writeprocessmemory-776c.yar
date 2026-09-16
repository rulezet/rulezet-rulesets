rule TTP_XOR_WriteProcessMemory_776c {
  strings:
    $key_776c = { 20 1e [2] 12 3c [2] 14 09 [2] 3a 09 [2] 05 15 }

  condition:
    any of them
}