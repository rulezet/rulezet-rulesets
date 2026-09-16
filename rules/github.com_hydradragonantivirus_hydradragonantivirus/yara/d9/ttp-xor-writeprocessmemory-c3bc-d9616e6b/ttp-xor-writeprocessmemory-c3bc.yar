rule TTP_XOR_WriteProcessMemory_c3bc {
  strings:
    $key_c3bc = { 94 ce [2] a6 ec [2] a0 d9 [2] 8e d9 [2] b1 c5 }

  condition:
    any of them
}