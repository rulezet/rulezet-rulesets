rule TTP_XOR_WriteProcessMemory_2cc9 {
  strings:
    $key_2cc9 = { 7b bb [2] 49 99 [2] 4f ac [2] 61 ac [2] 5e b0 }

  condition:
    any of them
}