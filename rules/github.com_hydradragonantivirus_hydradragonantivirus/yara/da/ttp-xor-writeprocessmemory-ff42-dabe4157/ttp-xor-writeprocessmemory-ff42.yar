rule TTP_XOR_WriteProcessMemory_ff42 {
  strings:
    $key_ff42 = { a8 30 [2] 9a 12 [2] 9c 27 [2] b2 27 [2] 8d 3b }

  condition:
    any of them
}