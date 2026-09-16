rule TTP_XOR_WriteProcessMemory_f9c9 {
  strings:
    $key_f9c9 = { ae bb [2] 9c 99 [2] 9a ac [2] b4 ac [2] 8b b0 }

  condition:
    any of them
}