rule TTP_XOR_WriteProcessMemory_465e {
  strings:
    $key_465e = { 11 2c [2] 23 0e [2] 25 3b [2] 0b 3b [2] 34 27 }

  condition:
    any of them
}