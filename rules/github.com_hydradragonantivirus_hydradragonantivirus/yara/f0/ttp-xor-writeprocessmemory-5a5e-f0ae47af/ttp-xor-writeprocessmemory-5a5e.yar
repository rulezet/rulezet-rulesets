rule TTP_XOR_WriteProcessMemory_5a5e {
  strings:
    $key_5a5e = { 0d 2c [2] 3f 0e [2] 39 3b [2] 17 3b [2] 28 27 }

  condition:
    any of them
}