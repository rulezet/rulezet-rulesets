rule TTP_XOR_WriteProcessMemory_1d4e {
  strings:
    $key_1d4e = { 4a 3c [2] 78 1e [2] 7e 2b [2] 50 2b [2] 6f 37 }

  condition:
    any of them
}