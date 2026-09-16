rule TTP_XOR_WriteProcessMemory_743e {
  strings:
    $key_743e = { 23 4c [2] 11 6e [2] 17 5b [2] 39 5b [2] 06 47 }

  condition:
    any of them
}