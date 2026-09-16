rule TTP_XOR_WriteProcessMemory_0e2b {
  strings:
    $key_0e2b = { 59 59 [2] 6b 7b [2] 6d 4e [2] 43 4e [2] 7c 52 }

  condition:
    any of them
}