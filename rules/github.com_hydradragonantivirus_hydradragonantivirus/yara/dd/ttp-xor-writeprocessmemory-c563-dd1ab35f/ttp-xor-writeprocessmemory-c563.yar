rule TTP_XOR_WriteProcessMemory_c563 {
  strings:
    $key_c563 = { 92 11 [2] a0 33 [2] a6 06 [2] 88 06 [2] b7 1a }

  condition:
    any of them
}