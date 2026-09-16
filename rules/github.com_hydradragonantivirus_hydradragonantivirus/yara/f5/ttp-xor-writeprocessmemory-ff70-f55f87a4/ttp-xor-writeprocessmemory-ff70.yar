rule TTP_XOR_WriteProcessMemory_ff70 {
  strings:
    $key_ff70 = { a8 02 [2] 9a 20 [2] 9c 15 [2] b2 15 [2] 8d 09 }

  condition:
    any of them
}