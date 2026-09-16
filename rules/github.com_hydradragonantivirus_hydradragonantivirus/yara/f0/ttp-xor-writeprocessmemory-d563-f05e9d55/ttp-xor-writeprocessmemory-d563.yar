rule TTP_XOR_WriteProcessMemory_d563 {
  strings:
    $key_d563 = { 82 11 [2] b0 33 [2] b6 06 [2] 98 06 [2] a7 1a }

  condition:
    any of them
}