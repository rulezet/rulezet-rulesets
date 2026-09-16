rule TTP_XOR_WriteProcessMemory_ff77 {
  strings:
    $key_ff77 = { a8 05 [2] 9a 27 [2] 9c 12 [2] b2 12 [2] 8d 0e }

  condition:
    any of them
}