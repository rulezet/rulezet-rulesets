rule TTP_XOR_WriteProcessMemory_2cc0 {
  strings:
    $key_2cc0 = { 7b b2 [2] 49 90 [2] 4f a5 [2] 61 a5 [2] 5e b9 }

  condition:
    any of them
}