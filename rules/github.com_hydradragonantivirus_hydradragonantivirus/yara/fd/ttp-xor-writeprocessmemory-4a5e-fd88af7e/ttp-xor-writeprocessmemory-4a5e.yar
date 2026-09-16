rule TTP_XOR_WriteProcessMemory_4a5e {
  strings:
    $key_4a5e = { 1d 2c [2] 2f 0e [2] 29 3b [2] 07 3b [2] 38 27 }

  condition:
    any of them
}