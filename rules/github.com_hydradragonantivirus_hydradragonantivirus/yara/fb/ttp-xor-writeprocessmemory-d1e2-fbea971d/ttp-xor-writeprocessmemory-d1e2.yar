rule TTP_XOR_WriteProcessMemory_d1e2 {
  strings:
    $key_d1e2 = { 86 90 [2] b4 b2 [2] b2 87 [2] 9c 87 [2] a3 9b }

  condition:
    any of them
}