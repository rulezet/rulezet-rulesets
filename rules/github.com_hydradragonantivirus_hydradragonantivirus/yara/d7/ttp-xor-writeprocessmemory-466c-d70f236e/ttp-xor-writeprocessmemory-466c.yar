rule TTP_XOR_WriteProcessMemory_466c {
  strings:
    $key_466c = { 11 1e [2] 23 3c [2] 25 09 [2] 0b 09 [2] 34 15 }

  condition:
    any of them
}