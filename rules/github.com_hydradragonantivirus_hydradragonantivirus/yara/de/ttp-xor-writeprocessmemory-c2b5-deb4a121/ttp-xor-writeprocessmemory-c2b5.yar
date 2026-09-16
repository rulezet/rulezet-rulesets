rule TTP_XOR_WriteProcessMemory_c2b5 {
  strings:
    $key_c2b5 = { 95 c7 [2] a7 e5 [2] a1 d0 [2] 8f d0 [2] b0 cc }

  condition:
    any of them
}