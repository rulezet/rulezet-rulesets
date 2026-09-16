rule TTP_XOR_WriteProcessMemory_43fc {
  strings:
    $key_43fc = { 14 8e [2] 26 ac [2] 20 99 [2] 0e 99 [2] 31 85 }

  condition:
    any of them
}