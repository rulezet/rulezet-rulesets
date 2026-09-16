rule TTP_XOR_WriteProcessMemory_872b {
  strings:
    $key_872b = { d0 59 [2] e2 7b [2] e4 4e [2] ca 4e [2] f5 52 }

  condition:
    any of them
}