rule TTP_XOR_WriteProcessMemory_0e5c {
  strings:
    $key_0e5c = { 59 2e [2] 6b 0c [2] 6d 39 [2] 43 39 [2] 7c 25 }

  condition:
    any of them
}