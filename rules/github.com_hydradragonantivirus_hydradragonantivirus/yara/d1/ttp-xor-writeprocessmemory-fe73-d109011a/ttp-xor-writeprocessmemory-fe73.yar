rule TTP_XOR_WriteProcessMemory_fe73 {
  strings:
    $key_fe73 = { a9 01 [2] 9b 23 [2] 9d 16 [2] b3 16 [2] 8c 0a }

  condition:
    any of them
}