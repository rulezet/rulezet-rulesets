rule TTP_XOR_WriteProcessMemory_400c {
  strings:
    $key_400c = { 17 7e [2] 25 5c [2] 23 69 [2] 0d 69 [2] 32 75 }

  condition:
    any of them
}