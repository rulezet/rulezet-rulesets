rule TTP_XOR_WriteProcessMemory_ff27 {
  strings:
    $key_ff27 = { a8 55 [2] 9a 77 [2] 9c 42 [2] b2 42 [2] 8d 5e }

  condition:
    any of them
}