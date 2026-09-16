rule TTP_XOR_WriteProcessMemory_21fc {
  strings:
    $key_21fc = { 76 8e [2] 44 ac [2] 42 99 [2] 6c 99 [2] 53 85 }

  condition:
    any of them
}