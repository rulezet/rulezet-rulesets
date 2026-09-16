rule TTP_XOR_WriteProcessMemory_c4b5 {
  strings:
    $key_c4b5 = { 93 c7 [2] a1 e5 [2] a7 d0 [2] 89 d0 [2] b6 cc }

  condition:
    any of them
}