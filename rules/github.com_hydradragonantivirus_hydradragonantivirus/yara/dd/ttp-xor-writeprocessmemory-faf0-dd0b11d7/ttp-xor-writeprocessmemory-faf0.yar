rule TTP_XOR_WriteProcessMemory_faf0 {
  strings:
    $key_faf0 = { ad 82 [2] 9f a0 [2] 99 95 [2] b7 95 [2] 88 89 }

  condition:
    any of them
}