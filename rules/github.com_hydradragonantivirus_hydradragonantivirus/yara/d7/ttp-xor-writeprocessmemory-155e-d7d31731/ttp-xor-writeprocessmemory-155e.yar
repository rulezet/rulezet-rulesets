rule TTP_XOR_WriteProcessMemory_155e {
  strings:
    $key_155e = { 42 2c [2] 70 0e [2] 76 3b [2] 58 3b [2] 67 27 }

  condition:
    any of them
}