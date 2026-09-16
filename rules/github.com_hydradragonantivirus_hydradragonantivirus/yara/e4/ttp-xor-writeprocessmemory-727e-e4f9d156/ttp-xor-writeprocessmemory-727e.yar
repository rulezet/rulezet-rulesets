rule TTP_XOR_WriteProcessMemory_727e {
  strings:
    $key_727e = { 25 0c [2] 17 2e [2] 11 1b [2] 3f 1b [2] 00 07 }

  condition:
    any of them
}