rule TTP_XOR_WriteProcessMemory_ff50 {
  strings:
    $key_ff50 = { a8 22 [2] 9a 00 [2] 9c 35 [2] b2 35 [2] 8d 29 }

  condition:
    any of them
}