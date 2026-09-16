rule TTP_XOR_WriteProcessMemory_fe60 {
  strings:
    $key_fe60 = { a9 12 [2] 9b 30 [2] 9d 05 [2] b3 05 [2] 8c 19 }

  condition:
    any of them
}