rule TTP_XOR_WriteProcessMemory_fc4e {
  strings:
    $key_fc4e = { ab 3c [2] 99 1e [2] 9f 2b [2] b1 2b [2] 8e 37 }

  condition:
    any of them
}