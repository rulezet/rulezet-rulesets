rule TTP_XOR_WriteProcessMemory_475e {
  strings:
    $key_475e = { 10 2c [2] 22 0e [2] 24 3b [2] 0a 3b [2] 35 27 }

  condition:
    any of them
}