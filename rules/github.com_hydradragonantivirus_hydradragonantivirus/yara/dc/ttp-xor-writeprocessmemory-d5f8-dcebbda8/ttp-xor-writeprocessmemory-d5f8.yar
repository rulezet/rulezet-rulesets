rule TTP_XOR_WriteProcessMemory_d5f8 {
  strings:
    $key_d5f8 = { 82 8a [2] b0 a8 [2] b6 9d [2] 98 9d [2] a7 81 }

  condition:
    any of them
}