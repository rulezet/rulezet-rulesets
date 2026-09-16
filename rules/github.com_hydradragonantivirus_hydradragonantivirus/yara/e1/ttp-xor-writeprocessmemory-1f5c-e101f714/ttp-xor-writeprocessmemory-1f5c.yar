rule TTP_XOR_WriteProcessMemory_1f5c {
  strings:
    $key_1f5c = { 48 2e [2] 7a 0c [2] 7c 39 [2] 52 39 [2] 6d 25 }

  condition:
    any of them
}