rule TTP_XOR_WriteProcessMemory_d4fc {
  strings:
    $key_d4fc = { 83 8e [2] b1 ac [2] b7 99 [2] 99 99 [2] a6 85 }

  condition:
    any of them
}