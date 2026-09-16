rule TTP_XOR_WriteProcessMemory_ff15 {
  strings:
    $key_ff15 = { a8 67 [2] 9a 45 [2] 9c 70 [2] b2 70 [2] 8d 6c }

  condition:
    any of them
}