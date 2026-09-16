rule TTP_XOR_WriteProcessMemory_fee7 {
  strings:
    $key_fee7 = { a9 95 [2] 9b b7 [2] 9d 82 [2] b3 82 [2] 8c 9e }

  condition:
    any of them
}