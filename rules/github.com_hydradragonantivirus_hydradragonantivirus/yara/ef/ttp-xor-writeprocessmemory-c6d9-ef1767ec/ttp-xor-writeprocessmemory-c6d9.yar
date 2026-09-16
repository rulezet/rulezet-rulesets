rule TTP_XOR_WriteProcessMemory_c6d9 {
  strings:
    $key_c6d9 = { 91 ab [2] a3 89 [2] a5 bc [2] 8b bc [2] b4 a0 }

  condition:
    any of them
}