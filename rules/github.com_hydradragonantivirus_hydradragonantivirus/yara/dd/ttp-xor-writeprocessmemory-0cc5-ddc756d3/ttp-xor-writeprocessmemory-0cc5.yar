rule TTP_XOR_WriteProcessMemory_0cc5 {
  strings:
    $key_0cc5 = { 5b b7 [2] 69 95 [2] 6f a0 [2] 41 a0 [2] 7e bc }

  condition:
    any of them
}