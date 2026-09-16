rule TTP_XOR_WriteProcessMemory_725e {
  strings:
    $key_725e = { 25 2c [2] 17 0e [2] 11 3b [2] 3f 3b [2] 00 27 }

  condition:
    any of them
}