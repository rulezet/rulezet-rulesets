rule TTP_XOR_WriteProcessMemory_13fc {
  strings:
    $key_13fc = { 44 8e [2] 76 ac [2] 70 99 [2] 5e 99 [2] 61 85 }

  condition:
    any of them
}