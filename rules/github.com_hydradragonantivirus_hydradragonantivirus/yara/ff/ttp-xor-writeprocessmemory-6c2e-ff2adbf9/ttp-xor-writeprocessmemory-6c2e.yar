rule TTP_XOR_WriteProcessMemory_6c2e {
  strings:
    $key_6c2e = { 3b 5c [2] 09 7e [2] 0f 4b [2] 21 4b [2] 1e 57 }

  condition:
    any of them
}