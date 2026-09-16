rule TTP_XOR_WriteProcessMemory_59fc {
  strings:
    $key_59fc = { 0e 8e [2] 3c ac [2] 3a 99 [2] 14 99 [2] 2b 85 }

  condition:
    any of them
}