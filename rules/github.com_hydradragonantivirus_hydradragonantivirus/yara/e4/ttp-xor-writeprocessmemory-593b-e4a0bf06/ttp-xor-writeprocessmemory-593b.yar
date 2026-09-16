rule TTP_XOR_WriteProcessMemory_593b {
  strings:
    $key_593b = { 0e 49 [2] 3c 6b [2] 3a 5e [2] 14 5e [2] 2b 42 }

  condition:
    any of them
}