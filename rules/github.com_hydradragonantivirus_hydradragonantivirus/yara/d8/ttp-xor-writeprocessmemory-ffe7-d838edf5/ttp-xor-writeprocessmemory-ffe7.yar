rule TTP_XOR_WriteProcessMemory_ffe7 {
  strings:
    $key_ffe7 = { a8 95 [2] 9a b7 [2] 9c 82 [2] b2 82 [2] 8d 9e }

  condition:
    any of them
}