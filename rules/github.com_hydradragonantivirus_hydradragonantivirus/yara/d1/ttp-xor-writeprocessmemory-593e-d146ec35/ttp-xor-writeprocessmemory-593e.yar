rule TTP_XOR_WriteProcessMemory_593e {
  strings:
    $key_593e = { 0e 4c [2] 3c 6e [2] 3a 5b [2] 14 5b [2] 2b 47 }

  condition:
    any of them
}