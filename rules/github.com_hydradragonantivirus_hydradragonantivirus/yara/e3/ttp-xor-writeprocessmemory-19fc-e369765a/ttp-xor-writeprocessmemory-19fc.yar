rule TTP_XOR_WriteProcessMemory_19fc {
  strings:
    $key_19fc = { 4e 8e [2] 7c ac [2] 7a 99 [2] 54 99 [2] 6b 85 }

  condition:
    any of them
}