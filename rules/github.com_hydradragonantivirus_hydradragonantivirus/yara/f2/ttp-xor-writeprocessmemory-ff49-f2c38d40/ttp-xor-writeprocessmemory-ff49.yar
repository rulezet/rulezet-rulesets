rule TTP_XOR_WriteProcessMemory_ff49 {
  strings:
    $key_ff49 = { a8 3b [2] 9a 19 [2] 9c 2c [2] b2 2c [2] 8d 30 }

  condition:
    any of them
}