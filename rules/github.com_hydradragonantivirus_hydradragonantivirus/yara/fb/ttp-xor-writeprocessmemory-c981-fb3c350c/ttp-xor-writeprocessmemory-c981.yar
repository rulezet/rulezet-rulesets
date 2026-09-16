rule TTP_XOR_WriteProcessMemory_c981 {
  strings:
    $key_c981 = { 9e f3 [2] ac d1 [2] aa e4 [2] 84 e4 [2] bb f8 }

  condition:
    any of them
}