rule TTP_XOR_WriteProcessMemory_17fc {
  strings:
    $key_17fc = { 40 8e [2] 72 ac [2] 74 99 [2] 5a 99 [2] 65 85 }

  condition:
    any of them
}