rule TTP_XOR_WriteProcessMemory_fe03 {
  strings:
    $key_fe03 = { a9 71 [2] 9b 53 [2] 9d 66 [2] b3 66 [2] 8c 7a }

  condition:
    any of them
}