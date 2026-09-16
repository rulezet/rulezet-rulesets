rule TTP_XOR_WriteProcessMemory_d5e8 {
  strings:
    $key_d5e8 = { 82 9a [2] b0 b8 [2] b6 8d [2] 98 8d [2] a7 91 }

  condition:
    any of them
}