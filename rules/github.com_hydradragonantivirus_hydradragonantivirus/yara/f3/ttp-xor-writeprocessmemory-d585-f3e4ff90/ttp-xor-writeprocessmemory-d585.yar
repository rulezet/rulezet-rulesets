rule TTP_XOR_WriteProcessMemory_d585 {
  strings:
    $key_d585 = { 82 f7 [2] b0 d5 [2] b6 e0 [2] 98 e0 [2] a7 fc }

  condition:
    any of them
}