rule TTP_XOR_WriteProcessMemory_fcc9 {
  strings:
    $key_fcc9 = { ab bb [2] 99 99 [2] 9f ac [2] b1 ac [2] 8e b0 }

  condition:
    any of them
}