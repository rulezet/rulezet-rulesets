rule TTP_XOR_WriteProcessMemory_d346 {
  strings:
    $key_d346 = { 84 34 [2] b6 16 [2] b0 23 [2] 9e 23 [2] a1 3f }

  condition:
    any of them
}