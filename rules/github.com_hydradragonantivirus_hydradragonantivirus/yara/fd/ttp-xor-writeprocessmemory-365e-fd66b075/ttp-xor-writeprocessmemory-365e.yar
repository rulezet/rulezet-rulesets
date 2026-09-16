rule TTP_XOR_WriteProcessMemory_365e {
  strings:
    $key_365e = { 61 2c [2] 53 0e [2] 55 3b [2] 7b 3b [2] 44 27 }

  condition:
    any of them
}