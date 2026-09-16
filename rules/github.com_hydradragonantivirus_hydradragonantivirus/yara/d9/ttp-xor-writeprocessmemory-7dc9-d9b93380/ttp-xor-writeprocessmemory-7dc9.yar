rule TTP_XOR_WriteProcessMemory_7dc9 {
  strings:
    $key_7dc9 = { 2a bb [2] 18 99 [2] 1e ac [2] 30 ac [2] 0f b0 }

  condition:
    any of them
}