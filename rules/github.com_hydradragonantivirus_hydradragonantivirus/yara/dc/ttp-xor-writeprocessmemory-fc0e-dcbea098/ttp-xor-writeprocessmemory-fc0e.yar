rule TTP_XOR_WriteProcessMemory_fc0e {
  strings:
    $key_fc0e = { ab 7c [2] 99 5e [2] 9f 6b [2] b1 6b [2] 8e 77 }

  condition:
    any of them
}