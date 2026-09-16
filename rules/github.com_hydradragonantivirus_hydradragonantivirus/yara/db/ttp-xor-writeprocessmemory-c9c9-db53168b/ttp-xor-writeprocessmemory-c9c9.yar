rule TTP_XOR_WriteProcessMemory_c9c9 {
  strings:
    $key_c9c9 = { 9e bb [2] ac 99 [2] aa ac [2] 84 ac [2] bb b0 }

  condition:
    any of them
}