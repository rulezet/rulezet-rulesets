rule TTP_XOR_WriteProcessMemory_744e {
  strings:
    $key_744e = { 23 3c [2] 11 1e [2] 17 2b [2] 39 2b [2] 06 37 }

  condition:
    any of them
}