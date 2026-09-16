rule TTP_XOR_WriteProcessMemory_d4e9 {
  strings:
    $key_d4e9 = { 83 9b [2] b1 b9 [2] b7 8c [2] 99 8c [2] a6 90 }

  condition:
    any of them
}