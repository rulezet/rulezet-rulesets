rule TTP_XOR_WriteProcessMemory_d0d0 {
  strings:
    $key_d0d0 = { 87 a2 [2] b5 80 [2] b3 b5 [2] 9d b5 [2] a2 a9 }

  condition:
    any of them
}