rule TTP_XOR_WriteProcessMemory_fc7e {
  strings:
    $key_fc7e = { ab 0c [2] 99 2e [2] 9f 1b [2] b1 1b [2] 8e 07 }

  condition:
    any of them
}