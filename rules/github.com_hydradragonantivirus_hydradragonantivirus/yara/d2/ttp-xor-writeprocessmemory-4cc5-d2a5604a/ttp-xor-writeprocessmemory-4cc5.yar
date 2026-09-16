rule TTP_XOR_WriteProcessMemory_4cc5 {
  strings:
    $key_4cc5 = { 1b b7 [2] 29 95 [2] 2f a0 [2] 01 a0 [2] 3e bc }

  condition:
    any of them
}