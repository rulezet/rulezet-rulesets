rule TTP_XOR_WriteProcessMemory_fef6 {
  strings:
    $key_fef6 = { a9 84 [2] 9b a6 [2] 9d 93 [2] b3 93 [2] 8c 8f }

  condition:
    any of them
}