rule TTP_XOR_WriteProcessMemory_d312 {
  strings:
    $key_d312 = { 84 60 [2] b6 42 [2] b0 77 [2] 9e 77 [2] a1 6b }

  condition:
    any of them
}