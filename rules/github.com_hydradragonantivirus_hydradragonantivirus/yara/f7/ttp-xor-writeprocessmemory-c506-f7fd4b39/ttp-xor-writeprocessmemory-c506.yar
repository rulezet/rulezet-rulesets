rule TTP_XOR_WriteProcessMemory_c506 {
  strings:
    $key_c506 = { 92 74 [2] a0 56 [2] a6 63 [2] 88 63 [2] b7 7f }

  condition:
    any of them
}