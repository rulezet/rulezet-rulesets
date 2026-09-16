rule TTP_XOR_WriteProcessMemory_22fc {
  strings:
    $key_22fc = { 75 8e [2] 47 ac [2] 41 99 [2] 6f 99 [2] 50 85 }

  condition:
    any of them
}