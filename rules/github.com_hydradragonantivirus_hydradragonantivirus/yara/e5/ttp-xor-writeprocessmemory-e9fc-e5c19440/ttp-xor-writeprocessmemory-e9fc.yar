rule TTP_XOR_WriteProcessMemory_e9fc {
  strings:
    $key_e9fc = { be 8e [2] 8c ac [2] 8a 99 [2] a4 99 [2] 9b 85 }

  condition:
    any of them
}