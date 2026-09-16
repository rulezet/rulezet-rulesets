rule TTP_XOR_WriteProcessMemory_5a4e {
  strings:
    $key_5a4e = { 0d 3c [2] 3f 1e [2] 39 2b [2] 17 2b [2] 28 37 }

  condition:
    any of them
}