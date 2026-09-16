rule TTP_XOR_WriteProcessMemory_fe51 {
  strings:
    $key_fe51 = { a9 23 [2] 9b 01 [2] 9d 34 [2] b3 34 [2] 8c 28 }

  condition:
    any of them
}