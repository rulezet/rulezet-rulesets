rule TTP_XOR_WriteProcessMemory_c282 {
  strings:
    $key_c282 = { 95 f0 [2] a7 d2 [2] a1 e7 [2] 8f e7 [2] b0 fb }

  condition:
    any of them
}