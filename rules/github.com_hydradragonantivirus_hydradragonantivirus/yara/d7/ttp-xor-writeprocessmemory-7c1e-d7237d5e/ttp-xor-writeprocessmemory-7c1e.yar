rule TTP_XOR_WriteProcessMemory_7c1e {
  strings:
    $key_7c1e = { 2b 6c [2] 19 4e [2] 1f 7b [2] 31 7b [2] 0e 67 }

  condition:
    any of them
}