rule TTP_XOR_WriteProcessMemory_c9c2 {
  strings:
    $key_c9c2 = { 9e b0 [2] ac 92 [2] aa a7 [2] 84 a7 [2] bb bb }

  condition:
    any of them
}