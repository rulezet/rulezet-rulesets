rule TTP_XOR_WriteProcessMemory_455e {
  strings:
    $key_455e = { 12 2c [2] 20 0e [2] 26 3b [2] 08 3b [2] 37 27 }

  condition:
    any of them
}