rule TTP_XOR_WriteProcessMemory_873e {
  strings:
    $key_873e = { d0 4c [2] e2 6e [2] e4 5b [2] ca 5b [2] f5 47 }

  condition:
    any of them
}