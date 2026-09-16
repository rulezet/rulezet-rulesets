rule TTP_XOR_WriteProcessMemory_37fc {
  strings:
    $key_37fc = { 60 8e [2] 52 ac [2] 54 99 [2] 7a 99 [2] 45 85 }

  condition:
    any of them
}