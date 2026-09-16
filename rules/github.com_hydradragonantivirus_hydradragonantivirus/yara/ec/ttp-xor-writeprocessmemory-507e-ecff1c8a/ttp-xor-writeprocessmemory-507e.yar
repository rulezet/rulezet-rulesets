rule TTP_XOR_WriteProcessMemory_507e {
  strings:
    $key_507e = { 07 0c [2] 35 2e [2] 33 1b [2] 1d 1b [2] 22 07 }

  condition:
    any of them
}