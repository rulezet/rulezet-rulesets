rule TTP_XOR_WriteProcessMemory_c940 {
  strings:
    $key_c940 = { 9e 32 [2] ac 10 [2] aa 25 [2] 84 25 [2] bb 39 }

  condition:
    any of them
}