rule TTP_XOR_WriteProcessMemory_ff17 {
  strings:
    $key_ff17 = { a8 65 [2] 9a 47 [2] 9c 72 [2] b2 72 [2] 8d 6e }

  condition:
    any of them
}