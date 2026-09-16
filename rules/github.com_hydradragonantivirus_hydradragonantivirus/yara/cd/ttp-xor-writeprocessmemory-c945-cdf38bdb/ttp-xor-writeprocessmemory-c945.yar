rule TTP_XOR_WriteProcessMemory_c945 {
  strings:
    $key_c945 = { 9e 37 [2] ac 15 [2] aa 20 [2] 84 20 [2] bb 3c }

  condition:
    any of them
}