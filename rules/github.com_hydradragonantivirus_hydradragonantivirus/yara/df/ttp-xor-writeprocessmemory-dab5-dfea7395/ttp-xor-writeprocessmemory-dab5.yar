rule TTP_XOR_WriteProcessMemory_dab5 {
  strings:
    $key_dab5 = { 8d c7 [2] bf e5 [2] b9 d0 [2] 97 d0 [2] a8 cc }

  condition:
    any of them
}