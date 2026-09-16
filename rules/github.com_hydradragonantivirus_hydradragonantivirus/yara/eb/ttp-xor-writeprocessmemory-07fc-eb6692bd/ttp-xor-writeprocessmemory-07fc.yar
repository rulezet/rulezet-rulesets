rule TTP_XOR_WriteProcessMemory_07fc {
  strings:
    $key_07fc = { 50 8e [2] 62 ac [2] 64 99 [2] 4a 99 [2] 75 85 }

  condition:
    any of them
}