rule TTP_XOR_WriteProcessMemory_3c4e {
  strings:
    $key_3c4e = { 6b 3c [2] 59 1e [2] 5f 2b [2] 71 2b [2] 4e 37 }

  condition:
    any of them
}