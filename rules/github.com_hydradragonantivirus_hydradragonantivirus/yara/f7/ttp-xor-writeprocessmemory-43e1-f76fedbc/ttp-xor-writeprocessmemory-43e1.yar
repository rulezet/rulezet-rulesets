rule TTP_XOR_WriteProcessMemory_43e1 {
  strings:
    $key_43e1 = { 14 93 [2] 26 b1 [2] 20 84 [2] 0e 84 [2] 31 98 }

  condition:
    any of them
}