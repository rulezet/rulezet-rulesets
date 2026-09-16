rule TTP_XOR_WriteProcessMemory_3b4e {
  strings:
    $key_3b4e = { 6c 3c [2] 5e 1e [2] 58 2b [2] 76 2b [2] 49 37 }

  condition:
    any of them
}