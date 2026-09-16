rule TTP_XOR_WriteProcessMemory_254e {
  strings:
    $key_254e = { 72 3c [2] 40 1e [2] 46 2b [2] 68 2b [2] 57 37 }

  condition:
    any of them
}