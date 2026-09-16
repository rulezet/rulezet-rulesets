rule TTP_XOR_WriteProcessMemory_163e {
  strings:
    $key_163e = { 41 4c [2] 73 6e [2] 75 5b [2] 5b 5b [2] 64 47 }

  condition:
    any of them
}