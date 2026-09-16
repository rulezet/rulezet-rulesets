rule TTP_XOR_WriteProcessMemory_03fc {
  strings:
    $key_03fc = { 54 8e [2] 66 ac [2] 60 99 [2] 4e 99 [2] 71 85 }

  condition:
    any of them
}