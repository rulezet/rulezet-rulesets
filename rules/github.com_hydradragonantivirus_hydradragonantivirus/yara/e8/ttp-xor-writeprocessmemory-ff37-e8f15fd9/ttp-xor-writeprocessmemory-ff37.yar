rule TTP_XOR_WriteProcessMemory_ff37 {
  strings:
    $key_ff37 = { a8 45 [2] 9a 67 [2] 9c 52 [2] b2 52 [2] 8d 4e }

  condition:
    any of them
}