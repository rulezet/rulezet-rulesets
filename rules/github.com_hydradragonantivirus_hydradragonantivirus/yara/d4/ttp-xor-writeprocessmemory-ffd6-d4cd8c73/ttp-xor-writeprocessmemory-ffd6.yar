rule TTP_XOR_WriteProcessMemory_ffd6 {
  strings:
    $key_ffd6 = { a8 a4 [2] 9a 86 [2] 9c b3 [2] b2 b3 [2] 8d af }

  condition:
    any of them
}