rule TTP_XOR_WriteProcessMemory_dbd5 {
  strings:
    $key_dbd5 = { 8c a7 [2] be 85 [2] b8 b0 [2] 96 b0 [2] a9 ac }

  condition:
    any of them
}