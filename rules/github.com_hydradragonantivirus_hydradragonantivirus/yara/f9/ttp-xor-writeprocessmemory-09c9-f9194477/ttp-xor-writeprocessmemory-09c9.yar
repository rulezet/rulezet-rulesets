rule TTP_XOR_WriteProcessMemory_09c9 {
  strings:
    $key_09c9 = { 5e bb [2] 6c 99 [2] 6a ac [2] 44 ac [2] 7b b0 }

  condition:
    any of them
}