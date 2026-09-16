rule TTP_XOR_WriteProcessMemory_faf5 {
  strings:
    $key_faf5 = { ad 87 [2] 9f a5 [2] 99 90 [2] b7 90 [2] 88 8c }

  condition:
    any of them
}