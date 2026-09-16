rule TTP_XOR_WriteProcessMemory_194e {
  strings:
    $key_194e = { 4e 3c [2] 7c 1e [2] 7a 2b [2] 54 2b [2] 6b 37 }

  condition:
    any of them
}