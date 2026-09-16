rule TTP_XOR_WriteProcessMemory_fff0 {
  strings:
    $key_fff0 = { a8 82 [2] 9a a0 [2] 9c 95 [2] b2 95 [2] 8d 89 }

  condition:
    any of them
}