rule TTP_XOR_WriteProcessMemory_e181 {
  strings:
    $key_e181 = { b6 f3 [2] 84 d1 [2] 82 e4 [2] ac e4 [2] 93 f8 }

  condition:
    any of them
}