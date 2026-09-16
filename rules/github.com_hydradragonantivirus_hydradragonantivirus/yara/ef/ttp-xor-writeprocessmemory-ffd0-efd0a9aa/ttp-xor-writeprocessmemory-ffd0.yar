rule TTP_XOR_WriteProcessMemory_ffd0 {
  strings:
    $key_ffd0 = { a8 a2 [2] 9a 80 [2] 9c b5 [2] b2 b5 [2] 8d a9 }

  condition:
    any of them
}