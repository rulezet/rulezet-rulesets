rule TTP_XOR_WriteProcessMemory_ff62 {
  strings:
    $key_ff62 = { a8 10 [2] 9a 32 [2] 9c 07 [2] b2 07 [2] 8d 1b }

  condition:
    any of them
}