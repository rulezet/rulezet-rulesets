rule TTP_XOR_WriteProcessMemory_d543 {
  strings:
    $key_d543 = { 82 31 [2] b0 13 [2] b6 26 [2] 98 26 [2] a7 3a }

  condition:
    any of them
}