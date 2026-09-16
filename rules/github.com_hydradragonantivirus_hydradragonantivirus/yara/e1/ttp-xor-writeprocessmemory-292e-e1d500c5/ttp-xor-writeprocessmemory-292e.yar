rule TTP_XOR_WriteProcessMemory_292e {
  strings:
    $key_292e = { 7e 5c [2] 4c 7e [2] 4a 4b [2] 64 4b [2] 5b 57 }

  condition:
    any of them
}