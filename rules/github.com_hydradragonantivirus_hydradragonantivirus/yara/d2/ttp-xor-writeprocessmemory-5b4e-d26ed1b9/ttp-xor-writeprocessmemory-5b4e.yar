rule TTP_XOR_WriteProcessMemory_5b4e {
  strings:
    $key_5b4e = { 0c 3c [2] 3e 1e [2] 38 2b [2] 16 2b [2] 29 37 }

  condition:
    any of them
}