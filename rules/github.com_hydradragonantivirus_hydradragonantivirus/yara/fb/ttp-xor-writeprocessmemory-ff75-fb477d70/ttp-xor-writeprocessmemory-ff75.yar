rule TTP_XOR_WriteProcessMemory_ff75 {
  strings:
    $key_ff75 = { a8 07 [2] 9a 25 [2] 9c 10 [2] b2 10 [2] 8d 0c }

  condition:
    any of them
}