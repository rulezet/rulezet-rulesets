rule TTP_XOR_WriteProcessMemory_535e {
  strings:
    $key_535e = { 04 2c [2] 36 0e [2] 30 3b [2] 1e 3b [2] 21 27 }

  condition:
    any of them
}