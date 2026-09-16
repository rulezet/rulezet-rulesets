rule TTP_XOR_WriteProcessMemory_7c2e {
  strings:
    $key_7c2e = { 2b 5c [2] 19 7e [2] 1f 4b [2] 31 4b [2] 0e 57 }

  condition:
    any of them
}