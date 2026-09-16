rule TTP_XOR_WriteProcessMemory_fe43 {
  strings:
    $key_fe43 = { a9 31 [2] 9b 13 [2] 9d 26 [2] b3 26 [2] 8c 3a }

  condition:
    any of them
}