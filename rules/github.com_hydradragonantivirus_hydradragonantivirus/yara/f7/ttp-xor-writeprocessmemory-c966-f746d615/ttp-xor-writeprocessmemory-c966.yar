rule TTP_XOR_WriteProcessMemory_c966 {
  strings:
    $key_c966 = { 9e 14 [2] ac 36 [2] aa 03 [2] 84 03 [2] bb 1f }

  condition:
    any of them
}