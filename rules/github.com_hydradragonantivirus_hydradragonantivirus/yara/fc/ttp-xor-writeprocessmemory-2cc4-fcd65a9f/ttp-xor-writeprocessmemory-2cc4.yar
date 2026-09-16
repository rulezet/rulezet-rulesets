rule TTP_XOR_WriteProcessMemory_2cc4 {
  strings:
    $key_2cc4 = { 7b b6 [2] 49 94 [2] 4f a1 [2] 61 a1 [2] 5e bd }

  condition:
    any of them
}