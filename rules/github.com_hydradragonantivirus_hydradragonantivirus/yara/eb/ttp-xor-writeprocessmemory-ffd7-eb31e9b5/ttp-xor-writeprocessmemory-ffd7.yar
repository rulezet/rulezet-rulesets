rule TTP_XOR_WriteProcessMemory_ffd7 {
  strings:
    $key_ffd7 = { a8 a5 [2] 9a 87 [2] 9c b2 [2] b2 b2 [2] 8d ae }

  condition:
    any of them
}