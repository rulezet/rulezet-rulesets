rule TTP_XOR_WriteProcessMemory_faf6 {
  strings:
    $key_faf6 = { ad 84 [2] 9f a6 [2] 99 93 [2] b7 93 [2] 88 8f }

  condition:
    any of them
}