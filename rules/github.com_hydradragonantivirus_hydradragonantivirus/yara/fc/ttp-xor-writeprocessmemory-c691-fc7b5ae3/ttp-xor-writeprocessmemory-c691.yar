rule TTP_XOR_WriteProcessMemory_c691 {
  strings:
    $key_c691 = { 91 e3 [2] a3 c1 [2] a5 f4 [2] 8b f4 [2] b4 e8 }

  condition:
    any of them
}