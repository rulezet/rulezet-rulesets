rule TTP_XOR_WriteProcessMemory_dab3 {
  strings:
    $key_dab3 = { 8d c1 [2] bf e3 [2] b9 d6 [2] 97 d6 [2] a8 ca }

  condition:
    any of them
}