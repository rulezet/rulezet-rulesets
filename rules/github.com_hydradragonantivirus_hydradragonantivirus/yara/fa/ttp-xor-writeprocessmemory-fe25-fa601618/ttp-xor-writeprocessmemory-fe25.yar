rule TTP_XOR_WriteProcessMemory_fe25 {
  strings:
    $key_fe25 = { a9 57 [2] 9b 75 [2] 9d 40 [2] b3 40 [2] 8c 5c }

  condition:
    any of them
}