rule TTP_XOR_WriteProcessMemory_c6c5 {
  strings:
    $key_c6c5 = { 91 b7 [2] a3 95 [2] a5 a0 [2] 8b a0 [2] b4 bc }

  condition:
    any of them
}