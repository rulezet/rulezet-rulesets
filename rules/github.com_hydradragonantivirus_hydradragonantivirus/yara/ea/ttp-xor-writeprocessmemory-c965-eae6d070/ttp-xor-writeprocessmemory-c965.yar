rule TTP_XOR_WriteProcessMemory_c965 {
  strings:
    $key_c965 = { 9e 17 [2] ac 35 [2] aa 00 [2] 84 00 [2] bb 1c }

  condition:
    any of them
}