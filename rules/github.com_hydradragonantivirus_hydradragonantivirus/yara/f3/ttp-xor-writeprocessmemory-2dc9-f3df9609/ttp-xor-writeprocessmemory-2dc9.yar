rule TTP_XOR_WriteProcessMemory_2dc9 {
  strings:
    $key_2dc9 = { 7a bb [2] 48 99 [2] 4e ac [2] 60 ac [2] 5f b0 }

  condition:
    any of them
}