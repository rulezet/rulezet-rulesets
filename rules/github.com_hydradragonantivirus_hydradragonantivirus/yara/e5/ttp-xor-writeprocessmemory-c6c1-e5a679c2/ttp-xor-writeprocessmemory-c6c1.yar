rule TTP_XOR_WriteProcessMemory_c6c1 {
  strings:
    $key_c6c1 = { 91 b3 [2] a3 91 [2] a5 a4 [2] 8b a4 [2] b4 b8 }

  condition:
    any of them
}