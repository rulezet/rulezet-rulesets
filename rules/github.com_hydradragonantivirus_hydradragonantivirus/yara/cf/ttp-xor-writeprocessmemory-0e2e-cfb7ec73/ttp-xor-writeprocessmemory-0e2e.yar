rule TTP_XOR_WriteProcessMemory_0e2e {
  strings:
    $key_0e2e = { 59 5c [2] 6b 7e [2] 6d 4b [2] 43 4b [2] 7c 57 }

  condition:
    any of them
}