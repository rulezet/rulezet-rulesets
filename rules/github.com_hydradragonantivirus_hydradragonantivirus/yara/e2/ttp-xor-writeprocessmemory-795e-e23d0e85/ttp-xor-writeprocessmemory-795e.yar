rule TTP_XOR_WriteProcessMemory_795e {
  strings:
    $key_795e = { 2e 2c [2] 1c 0e [2] 1a 3b [2] 34 3b [2] 0b 27 }

  condition:
    any of them
}