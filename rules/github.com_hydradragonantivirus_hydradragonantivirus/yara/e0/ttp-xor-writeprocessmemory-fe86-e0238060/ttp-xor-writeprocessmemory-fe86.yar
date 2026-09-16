rule TTP_XOR_WriteProcessMemory_fe86 {
  strings:
    $key_fe86 = { a9 f4 [2] 9b d6 [2] 9d e3 [2] b3 e3 [2] 8c ff }

  condition:
    any of them
}