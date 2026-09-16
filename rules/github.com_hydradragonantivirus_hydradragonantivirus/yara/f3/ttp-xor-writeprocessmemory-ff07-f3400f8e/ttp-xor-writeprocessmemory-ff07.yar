rule TTP_XOR_WriteProcessMemory_ff07 {
  strings:
    $key_ff07 = { a8 75 [2] 9a 57 [2] 9c 62 [2] b2 62 [2] 8d 7e }

  condition:
    any of them
}