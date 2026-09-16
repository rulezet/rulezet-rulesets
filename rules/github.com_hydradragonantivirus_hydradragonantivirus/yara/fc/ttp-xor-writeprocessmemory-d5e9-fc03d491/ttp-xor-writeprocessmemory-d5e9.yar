rule TTP_XOR_WriteProcessMemory_d5e9 {
  strings:
    $key_d5e9 = { 82 9b [2] b0 b9 [2] b6 8c [2] 98 8c [2] a7 90 }

  condition:
    any of them
}