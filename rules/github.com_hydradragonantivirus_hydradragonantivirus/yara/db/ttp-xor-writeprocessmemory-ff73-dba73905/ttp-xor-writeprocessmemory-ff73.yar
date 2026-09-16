rule TTP_XOR_WriteProcessMemory_ff73 {
  strings:
    $key_ff73 = { a8 01 [2] 9a 23 [2] 9c 16 [2] b2 16 [2] 8d 0a }

  condition:
    any of them
}