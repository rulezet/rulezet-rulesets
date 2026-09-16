rule TTP_XOR_WriteProcessMemory_44fc {
  strings:
    $key_44fc = { 13 8e [2] 21 ac [2] 27 99 [2] 09 99 [2] 36 85 }

  condition:
    any of them
}