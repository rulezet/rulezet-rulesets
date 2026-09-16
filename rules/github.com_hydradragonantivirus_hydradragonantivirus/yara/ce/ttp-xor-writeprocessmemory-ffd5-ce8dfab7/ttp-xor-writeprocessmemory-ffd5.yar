rule TTP_XOR_WriteProcessMemory_ffd5 {
  strings:
    $key_ffd5 = { a8 a7 [2] 9a 85 [2] 9c b0 [2] b2 b0 [2] 8d ac }

  condition:
    any of them
}