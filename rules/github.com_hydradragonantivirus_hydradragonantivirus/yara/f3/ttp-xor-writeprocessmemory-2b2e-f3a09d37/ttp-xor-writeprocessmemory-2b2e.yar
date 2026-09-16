rule TTP_XOR_WriteProcessMemory_2b2e {
  strings:
    $key_2b2e = { 7c 5c [2] 4e 7e [2] 48 4b [2] 66 4b [2] 59 57 }

  condition:
    any of them
}