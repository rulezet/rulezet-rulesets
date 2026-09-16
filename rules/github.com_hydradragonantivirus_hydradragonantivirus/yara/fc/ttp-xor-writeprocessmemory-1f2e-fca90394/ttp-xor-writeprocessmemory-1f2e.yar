rule TTP_XOR_WriteProcessMemory_1f2e {
  strings:
    $key_1f2e = { 48 5c [2] 7a 7e [2] 7c 4b [2] 52 4b [2] 6d 57 }

  condition:
    any of them
}