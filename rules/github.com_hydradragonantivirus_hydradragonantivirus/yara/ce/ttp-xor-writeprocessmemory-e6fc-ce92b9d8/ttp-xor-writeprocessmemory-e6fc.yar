rule TTP_XOR_WriteProcessMemory_e6fc {
  strings:
    $key_e6fc = { b1 8e [2] 83 ac [2] 85 99 [2] ab 99 [2] 94 85 }

  condition:
    any of them
}