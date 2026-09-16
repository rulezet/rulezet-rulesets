rule TTP_XOR_WriteProcessMemory_fc5e {
  strings:
    $key_fc5e = { ab 2c [2] 99 0e [2] 9f 3b [2] b1 3b [2] 8e 27 }

  condition:
    any of them
}