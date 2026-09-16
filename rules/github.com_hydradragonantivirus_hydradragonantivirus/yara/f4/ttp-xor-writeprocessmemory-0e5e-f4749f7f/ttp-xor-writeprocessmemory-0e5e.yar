rule TTP_XOR_WriteProcessMemory_0e5e {
  strings:
    $key_0e5e = { 59 2c [2] 6b 0e [2] 6d 3b [2] 43 3b [2] 7c 27 }

  condition:
    any of them
}