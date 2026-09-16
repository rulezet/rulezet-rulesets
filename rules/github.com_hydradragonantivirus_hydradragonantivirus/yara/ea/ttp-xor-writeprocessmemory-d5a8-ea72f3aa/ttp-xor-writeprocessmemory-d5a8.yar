rule TTP_XOR_WriteProcessMemory_d5a8 {
  strings:
    $key_d5a8 = { 82 da [2] b0 f8 [2] b6 cd [2] 98 cd [2] a7 d1 }

  condition:
    any of them
}