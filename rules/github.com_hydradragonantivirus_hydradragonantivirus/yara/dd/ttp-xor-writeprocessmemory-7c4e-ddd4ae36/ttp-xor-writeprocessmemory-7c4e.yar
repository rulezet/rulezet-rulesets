rule TTP_XOR_WriteProcessMemory_7c4e {
  strings:
    $key_7c4e = { 2b 3c [2] 19 1e [2] 1f 2b [2] 31 2b [2] 0e 37 }

  condition:
    any of them
}