rule TTP_XOR_WriteProcessMemory_f85e {
  strings:
    $key_f85e = { af 2c [2] 9d 0e [2] 9b 3b [2] b5 3b [2] 8a 27 }

  condition:
    any of them
}