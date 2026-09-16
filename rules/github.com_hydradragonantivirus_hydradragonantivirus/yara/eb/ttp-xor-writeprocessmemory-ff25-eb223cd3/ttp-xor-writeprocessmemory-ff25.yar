rule TTP_XOR_WriteProcessMemory_ff25 {
  strings:
    $key_ff25 = { a8 57 [2] 9a 75 [2] 9c 40 [2] b2 40 [2] 8d 5c }

  condition:
    any of them
}