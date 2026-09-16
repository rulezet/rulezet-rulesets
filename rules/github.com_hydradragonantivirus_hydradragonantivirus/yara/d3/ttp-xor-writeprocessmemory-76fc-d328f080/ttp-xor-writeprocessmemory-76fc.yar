rule TTP_XOR_WriteProcessMemory_76fc {
  strings:
    $key_76fc = { 21 8e [2] 13 ac [2] 15 99 [2] 3b 99 [2] 04 85 }

  condition:
    any of them
}