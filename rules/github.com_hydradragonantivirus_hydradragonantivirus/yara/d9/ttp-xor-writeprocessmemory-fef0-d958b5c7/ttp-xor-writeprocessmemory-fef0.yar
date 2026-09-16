rule TTP_XOR_WriteProcessMemory_fef0 {
  strings:
    $key_fef0 = { a9 82 [2] 9b a0 [2] 9d 95 [2] b3 95 [2] 8c 89 }

  condition:
    any of them
}