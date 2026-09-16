rule TTP_XOR_WriteProcessMemory_ff02 {
  strings:
    $key_ff02 = { a8 70 [2] 9a 52 [2] 9c 67 [2] b2 67 [2] 8d 7b }

  condition:
    any of them
}