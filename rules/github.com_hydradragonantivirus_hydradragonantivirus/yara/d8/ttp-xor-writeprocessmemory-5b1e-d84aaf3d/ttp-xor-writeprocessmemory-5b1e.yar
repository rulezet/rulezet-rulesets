rule TTP_XOR_WriteProcessMemory_5b1e {
  strings:
    $key_5b1e = { 0c 6c [2] 3e 4e [2] 38 7b [2] 16 7b [2] 29 67 }

  condition:
    any of them
}