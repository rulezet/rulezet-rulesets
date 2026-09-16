rule TTP_XOR_WriteProcessMemory_c153 {
  strings:
    $key_c153 = { 96 21 [2] a4 03 [2] a2 36 [2] 8c 36 [2] b3 2a }

  condition:
    any of them
}