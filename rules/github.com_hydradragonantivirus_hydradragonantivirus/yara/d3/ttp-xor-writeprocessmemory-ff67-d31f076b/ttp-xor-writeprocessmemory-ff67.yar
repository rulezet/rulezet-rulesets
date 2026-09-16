rule TTP_XOR_WriteProcessMemory_ff67 {
  strings:
    $key_ff67 = { a8 15 [2] 9a 37 [2] 9c 02 [2] b2 02 [2] 8d 1e }

  condition:
    any of them
}