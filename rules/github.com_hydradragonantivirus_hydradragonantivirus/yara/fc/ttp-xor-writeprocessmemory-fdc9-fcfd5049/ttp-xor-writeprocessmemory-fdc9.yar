rule TTP_XOR_WriteProcessMemory_fdc9 {
  strings:
    $key_fdc9 = { aa bb [2] 98 99 [2] 9e ac [2] b0 ac [2] 8f b0 }

  condition:
    any of them
}