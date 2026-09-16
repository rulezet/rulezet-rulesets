rule TTP_XOR_WriteProcessMemory_d0e2 {
  strings:
    $key_d0e2 = { 87 90 [2] b5 b2 [2] b3 87 [2] 9d 87 [2] a2 9b }

  condition:
    any of them
}