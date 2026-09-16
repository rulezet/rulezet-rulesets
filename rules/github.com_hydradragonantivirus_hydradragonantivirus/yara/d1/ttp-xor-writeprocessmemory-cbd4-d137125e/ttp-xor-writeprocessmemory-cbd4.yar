rule TTP_XOR_WriteProcessMemory_cbd4 {
  strings:
    $key_cbd4 = { 9c a6 [2] ae 84 [2] a8 b1 [2] 86 b1 [2] b9 ad }

  condition:
    any of them
}