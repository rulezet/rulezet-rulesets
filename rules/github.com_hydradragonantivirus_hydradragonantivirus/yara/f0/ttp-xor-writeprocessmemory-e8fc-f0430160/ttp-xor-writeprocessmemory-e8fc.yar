rule TTP_XOR_WriteProcessMemory_e8fc {
  strings:
    $key_e8fc = { bf 8e [2] 8d ac [2] 8b 99 [2] a5 99 [2] 9a 85 }

  condition:
    any of them
}