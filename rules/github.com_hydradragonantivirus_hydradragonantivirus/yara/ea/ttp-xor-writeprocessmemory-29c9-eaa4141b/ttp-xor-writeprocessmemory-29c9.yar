rule TTP_XOR_WriteProcessMemory_29c9 {
  strings:
    $key_29c9 = { 7e bb [2] 4c 99 [2] 4a ac [2] 64 ac [2] 5b b0 }

  condition:
    any of them
}